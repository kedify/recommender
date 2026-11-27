// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

func existingLimitFixture(pressured bool) (Input, Policy) {
	in := fixture(6000, 60)
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch}
	c.CPU.CurrentRequest.Value, c.CPU.CurrentLimit.Value = 300, 350
	for i := range c.CPU.Series[0].Samples {
		c.CPU.Series[0].Samples[i].Value = 100
	}
	// A higher earlier quota in this runtime let the Pod demonstrate recurring
	// demand close to the 500m policy candidate. Under today's cap its usage
	// alone cannot establish how much more CPU it would use.
	for i := 0; i < 3; i++ {
		c.CPU.Series[0].Samples[i].Value = 490
	}
	counter := func(step float64) []Series {
		s := guardFamily("runtime", "pod-1", guardRamp(101, step))
		s.CPUGuardStart = epoch + 4*60000
		return []Series{s}
	}
	increments := 0.0
	if pressured {
		increments = 1
	}
	c.Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{
		SourceComplete: true, CoverageAt: in.EvaluationTime, Periods: counter(100), ThrottledPeriods: counter(increments), Seconds: counter(increments),
	}}
	p := shortPolicy()
	p.CPU.HeadroomCoefficient = 1
	p.CPU.RequestsOnly, p.CPU.ExistingLimitsOnly, p.Memory.SafetyGuards = true, true, true
	return in, p
}

func TestExistingCPULimitsPreservePrimarySizingAndGuardEstimates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*ContainerObservation)
		pressure bool
		want     float64
		reason   Reason
	}{
		{"verified increase", nil, true, 500, ""},
		{"request above retained cap stays held", func(c *ContainerObservation) {
			c.CPU.CurrentLimit.Value, c.CPU.CurrentRequest.Value = 80, 10
		}, true, 500, ""},
		{"ratio without pressure", nil, false, 0, ReasonCPUIncreaseNoPressure},
		{"pressure without measured amount", func(c *ContainerObservation) {
			for i := 0; i < 3; i++ {
				c.CPU.Series[0].Samples[i].Value = 349.9999
			}
		}, true, 0, ReasonCPUIncreaseDemandUnknown},
		{"pressure with materially different demand", func(c *ContainerObservation) {
			for i := 0; i < 3; i++ {
				c.CPU.Series[0].Samples[i].Value = 900
			}
		}, true, 0, ReasonCPUIncreaseDemandUnknown},
		{"verified cut", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 1000 }, false, 500, ""},
		{"pressured cut", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 1000 }, true, 0, ReasonCPUThrottlingPressure},
		{"higher recurring bursts block cut", func(c *ContainerObservation) {
			c.CPU.CurrentLimit.Value = 1000
			for i := 0; i < 3; i++ {
				c.CPU.Series[0].Samples[i].Value = 700
			}
		}, false, 0, ReasonCPULimitBelowDemand},
		{"materially unchanged", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 525 }, false, 0, ReasonNoMaterialChange},
		{"known uncapped", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 0; c.CPU.CurrentLimit.Unset = true }, false, 0, ReasonLimitDisabled},
		{"numeric zero", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 0 }, false, 0, ReasonLimitDisabled},
		{"unavailable cap", func(c *ContainerObservation) { c.CPU.CurrentLimit = Signal{} }, true, 0, ReasonMissingLimit},
		{"stale cap", func(c *ContainerObservation) { c.CPU.CurrentLimit.Timestamp = epoch }, true, 0, ReasonStaleLimit},
		{"old collector without applied quota", func(c *ContainerObservation) { c.Classification.Throttling.Seconds[0].CPUGuardStart = 0 }, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"old collector without current runtime", func(c *ContainerObservation) { c.Inventory.CurrentPods = nil }, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"extra current Pod without measurements", func(c *ContainerObservation) { c.Inventory.CurrentPods["unmeasured"] = epoch }, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"missing denominator", func(c *ContainerObservation) { c.Classification.Throttling.Periods = nil }, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"unavailable source", func(c *ContainerObservation) { c.Classification.Throttling.SourceComplete = false }, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"new quota has only one sample", func(c *ContainerObservation) {
			c.Classification.Throttling.Seconds[0].CPUGuardStart = c.Inventory.Timestamp
		}, true, 0, ReasonCPULimitEvidenceIncomplete},
		{"terminal reset", func(c *ContainerObservation) { c.Classification.Throttling.Periods[0].Samples[100].Value = 0 }, true, 0, ReasonCPULimitEvidenceIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, p := existingLimitFixture(tc.pressure)
			if tc.mutate != nil {
				tc.mutate(&in.Containers[0])
			}
			base := p
			base.CPU.ExistingLimitsOnly = false
			old := run(t, in, base)
			got := run(t, in, p)
			if !reflect.DeepEqual(old.Results[0], got.Results[0]) {
				t.Fatal("memory changed")
			}
			q, exists := guardRecommendation(old.Results[1], SettingRequests)
			req, has := guardRecommendation(got.Results[1], SettingRequests)
			if q != req || exists != has || !reflect.DeepEqual(guardSettingTrace(old.Results[1], SettingRequests), guardSettingTrace(got.Results[1], SettingRequests)) {
				t.Fatal("primary CPU request changed")
			}
			cap, has := guardRecommendation(got.Results[1], SettingLimits)
			trace := guardSettingTrace(got.Results[1], SettingLimits)
			if has != (tc.want > 0) || cap.SuggestedValue != tc.want || tc.reason != "" && !slices.Contains(trace.Reasons, tc.reason) {
				t.Fatalf("cap=%+v, trace=%+v", cap, trace)
			}
			if !got.EffectivePolicy.CPU.ExistingLimitsOnly || got.EffectivePolicy.CPU.LimitReductionGuard == nil {
				t.Fatal("existing-only cap guard missing from replay policy")
			}
			if replay := run(t, in, got.EffectivePolicy); !reflect.DeepEqual(replay, got) {
				t.Fatal("recorded policy does not reproduce the result")
			}
		})
	}
}

func TestExistingLimitGuardsPreservePrimaryReleaseSelection(t *testing.T) {
	in, p := existingLimitFixture(false)
	c := &in.Containers[0]
	p.Memory.SafetyGuards = false
	c.CPU.CurrentLimit.Value = 1000
	// Primary usage detects an earlier transition; the cap proof must still
	// see the more recent transition that appears only in CFS.
	c.Memory.Series = append(c.Memory.Series, guardCounter("early-rollout", "C", epoch+10*60000, []float64{1}))
	// This runtime began after an intervening rollout visible only in CFS.
	c.Inventory.CurrentPods["pod-1"] = in.EvaluationTime - 4*60000
	throttling := &c.Classification.Throttling
	throttling.Periods = append(throttling.Periods, guardCounter("intervening", "B", in.EvaluationTime-5*60000, []float64{1}))
	for _, strictPrimary := range []bool{false, true} {
		p.CPU.LimitReductionGuard = &CPULimitReductionGuardPolicy{RequireCompleteCoverage: strictPrimary}
		base := p
		base.CPU.ExistingLimitsOnly = false
		primary := run(t, in, base)
		out := run(t, in, p)
		if !reflect.DeepEqual(primary.Results[0], out.Results[0]) || !reflect.DeepEqual(guardSettingTrace(primary.Results[1], SettingRequests), guardSettingTrace(out.Results[1], SettingRequests)) {
			t.Fatalf("secondary guard changed primary sizing (strict primary=%t)", strictPrimary)
		}
		if _, ok := guardRecommendation(out.Results[1], SettingLimits); ok {
			t.Fatal("a candidate based on demand from before the rollback produced a cap proposal")
		}
		if replay := run(t, in, out.EffectivePolicy); !reflect.DeepEqual(out, replay) {
			t.Fatal("effective policy changed primary or cap release selection on replay")
		}
	}
}

func TestRaiseCannotCombinePressureAndDemandFromDifferentReplicas(t *testing.T) {
	in, policy := existingLimitFixture(true)
	c := &in.Containers[0]
	second := c.CPU.Series[0]
	second.ID, second.PodUID = "other-runtime", "other-pod"
	second.Samples = slices.Clone(second.Samples)
	c.CPU.Series = append(c.CPU.Series, second)
	// The first Pod is pressured. Only the second Pod ever used 490m.
	for i := 0; i < 3; i++ {
		c.CPU.Series[0].Samples[i].Value = 100
	}
	c.Inventory.CurrentPods[second.PodUID] = epoch
	c.Inventory.Eligible, c.Inventory.Observed = 2, 2
	obs := &c.Classification.Throttling
	for _, family := range []*[]Series{&obs.Periods, &obs.ThrottledPeriods, &obs.Seconds} {
		peer := (*family)[0]
		peer.ID, peer.PodUID = second.ID, second.PodUID
		peer.Samples = slices.Clone(peer.Samples)
		if family != &obs.Periods {
			for i := range peer.Samples {
				peer.Samples[i].Value = 0
			}
		}
		*family = append(*family, peer)
	}
	cpu := run(t, in, policy).Results[1]
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !slices.Contains(guardSettingTrace(cpu, SettingLimits).Reasons, ReasonCPUIncreaseDemandUnknown) {
		t.Fatalf("cross-replica demand authorized an increase: %+v", cpu)
	}
}

func TestExistingLimitsCannotEnableLegacyFullLimitSizing(t *testing.T) {
	in, p := existingLimitFixture(true)
	p.CPU.RequestsOnly = false
	if _, err := Analyze(in, p); err == nil {
		t.Fatal("accepted conflicting primary request strategy")
	}
	p.CPU.RequestsOnly = true
	out := run(t, in, p)
	// Decode the policy as an earlier reader, which ignores the additive field.
	raw, _ := json.Marshal(out.EffectivePolicy)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	var cpu map[string]json.RawMessage
	if err := json.Unmarshal(obj["cpu"], &cpu); err != nil {
		t.Fatal(err)
	}
	delete(cpu, "existingLimitsOnly")
	obj["cpu"], _ = json.Marshal(cpu)
	raw, _ = json.Marshal(obj)
	var old Policy
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if _, has := guardRecommendation(run(t, in, old).Results[1], SettingLimits); has {
		t.Fatal("legacy reader generated cap advice")
	}
}
