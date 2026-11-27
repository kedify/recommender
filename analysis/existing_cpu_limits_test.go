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
		{"pressure with measured demand above the candidate", func(c *ContainerObservation) {
			for i := 0; i < 3; i++ {
				c.CPU.Series[0].Samples[i].Value = 900
			}
		}, true, 500, ""},
		{"candidate materially exceeds measured headroom", func(c *ContainerObservation) {
			for i := 0; i < 3; i++ {
				c.CPU.Series[0].Samples[i].Value = 400
			}
		}, true, 0, ReasonCPUIncreaseDemandUnknown},
		{"verified cut", func(c *ContainerObservation) { c.CPU.CurrentLimit.Value = 1000 }, false, 500, ""},
		{"cut without applied quota", func(c *ContainerObservation) {
			c.CPU.CurrentLimit.Value = 1000
			c.Classification.Throttling.Seconds[0].CPUGuardStart = 0
		}, false, 0, ReasonCPULimitEvidenceIncomplete},
		{"cut without current runtime", func(c *ContainerObservation) {
			c.CPU.CurrentLimit.Value = 1000
			c.Inventory.CurrentPods = nil
		}, false, 0, ReasonCPULimitEvidenceIncomplete},
		{"cut with only one sample at current quota", func(c *ContainerObservation) {
			c.CPU.CurrentLimit.Value = 1000
			c.Classification.Throttling.Seconds[0].CPUGuardStart = c.Inventory.Timestamp
		}, false, 0, ReasonCPULimitEvidenceIncomplete},
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
			if slices.Contains(got.Results[1].Notices, ReasonCPUIncreaseNoPressure) {
				t.Fatal("a healthy retained cap generated a notice")
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
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !slices.Equal(guardSettingTrace(cpu, SettingLimits).Reasons, []Reason{ReasonCPUIncreaseDemandUnknown}) {
		t.Fatalf("cross-replica demand authorized an increase: %+v", cpu)
	}
	for i := 0; i < 3; i++ {
		c.CPU.Series[0].Samples[i].Value = 490
	}
	if rec, ok := guardRecommendation(run(t, in, policy).Results[1], SettingLimits); !ok || rec.SuggestedValue != 500 {
		t.Fatalf("verified pressure and demand on the same replica did not support 500m: %+v", rec)
	}
}

func TestExistingCPULimitRequiresUsageAtTheProvenQuota(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		increase, counter               bool
		lastMinutesAgo, quotaMinutesAgo int
		currentCounterInterval, want    bool
	}{
		{name: "cut with usage before resized quota", lastMinutesAgo: 4, quotaMinutesAgo: 2},
		{name: "raise with usage before resized quota", increase: true, lastMinutesAgo: 4, quotaMinutesAgo: 2},
		{name: "usage before both proven CFS intervals", lastMinutesAgo: 4, quotaMinutesAgo: 10},
		{name: "independent gauge during CFS proof", lastMinutesAgo: 1, quotaMinutesAgo: 2, want: true},
		{name: "counter rate crossing quota change", counter: true, lastMinutesAgo: 1, quotaMinutesAgo: 2},
		{name: "entire counter rate at current quota", counter: true, lastMinutesAgo: 1, quotaMinutesAgo: 2, currentCounterInterval: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, p := existingLimitFixture(tc.increase)
			c := &in.Containers[0]
			if !tc.increase {
				c.CPU.CurrentLimit.Value = 1000
			}
			throttling := c.Classification.Throttling
			for _, rows := range [][]Series{throttling.Periods, throttling.ThrottledPeriods, throttling.Seconds} {
				rows[0].CPUGuardStart = in.EvaluationTime - int64(tc.quotaMinutesAgo)*60000
			}
			usage := &c.CPU.Series[0]
			usage.Samples = usage.Samples[:len(usage.Samples)-tc.lastMinutesAgo]
			if tc.counter {
				usage.Kind = SampleCPUCounterSeconds
				for i := range usage.Samples {
					usage.Samples[i].Value = float64(i) * 6
				}
				if !tc.currentCounterInterval {
					usage.Samples = slices.Delete(usage.Samples, len(usage.Samples)-2, len(usage.Samples)-1)
				}
			}
			cpu := run(t, in, p).Results[1]
			rec, issued := guardRecommendation(cpu, SettingLimits)
			if issued != tc.want || !issued && !slices.Contains(guardSettingTrace(cpu, SettingLimits).Reasons, ReasonCPULimitEvidenceIncomplete) {
				t.Fatalf("limit %+v, trace %+v", rec, guardSettingTrace(cpu, SettingLimits))
			}
		})
	}
}

func TestUsageAfterTheCertifiedCFSSnapshotCannotFillAGap(t *testing.T) {
	in, p := existingLimitFixture(false)
	c := &in.Containers[0]
	c.CPU.CurrentLimit.Value = 1000
	totals := &c.Classification.Throttling
	totals.CoverageAt = in.EvaluationTime - 4*60000
	for _, rows := range [][]Series{totals.Periods, totals.ThrottledPeriods, totals.Seconds} {
		rows[0].Samples = rows[0].Samples[:97]
	}
	// The certified CFS span covers minutes 94 through 96. CPU usage arrived
	// through minute 93 and resumed at 97, so both streams are fresh.
	c.CPU.Series[0].Samples = slices.Delete(c.CPU.Series[0].Samples, 94, 97)
	if _, issued := guardRecommendation(run(t, in, p).Results[1], SettingLimits); issued {
		t.Fatal("issued a cut without a usage observation inside the verified CFS span")
	}
	c.CPU.Series[0].Samples = append(c.CPU.Series[0].Samples, Sample{Timestamp: totals.CoverageAt - 27000, Value: 100})
	if rec, issued := guardRecommendation(run(t, in, p).Results[1], SettingLimits); !issued || rec.SuggestedValue != 500 {
		t.Fatalf("an independently timed usage observation inside the CFS span did not qualify: %+v", rec)
	}
}

func TestCounterUsageMustOverlapCertifiedCFS(t *testing.T) {
	for _, tc := range []struct {
		name        string
		last        int
		reset, want bool
	}{
		{"ends exactly where CFS starts", 94, false, false},
		{"only overlapping interval crosses a reset", 95, true, false},
		{"one valid overlapping rate", 95, false, true},
		{"valid rate after reset", 96, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, p := existingLimitFixture(false)
			c := &in.Containers[0]
			c.CPU.CurrentLimit.Value = 1000
			totals := &c.Classification.Throttling
			totals.CoverageAt = in.EvaluationTime - 4*60000
			for _, family := range [][]Series{totals.Periods, totals.ThrottledPeriods, totals.Seconds} {
				family[0].Samples = family[0].Samples[:97]
			}
			usage := &c.CPU.Series[0]
			usage.Kind = SampleCPUCounterSeconds
			for i := range usage.Samples {
				usage.Samples[i].Value = float64(i) * 6
				if tc.reset && i >= 95 {
					usage.Samples[i].Value = float64(i-95) * 6
				}
			}
			usage.Samples = slices.Delete(usage.Samples, tc.last+1, 97)
			cpu := run(t, in, p).Results[1]
			rec, issued := guardRecommendation(cpu, SettingLimits)
			if issued != tc.want || !issued && !slices.Contains(guardSettingTrace(cpu, SettingLimits).Reasons, ReasonCPULimitEvidenceIncomplete) {
				t.Fatalf("limit %+v, trace %+v", rec, guardSettingTrace(cpu, SettingLimits))
			}
		})
	}
}

func TestExistingLimitsCannotEnableLegacyFullLimitSizing(t *testing.T) {
	in, p := existingLimitFixture(true)
	p.CPU.RequestsOnly = false
	if _, err := Analyze(in, p); err == nil {
		t.Fatal("accepted conflicting primary request strategy")
	}
	p.CPU.RequestsOnly = true
	p.CPU.LimitReductionGuard = &CPULimitReductionGuardPolicy{RequireCompleteCoverage: true}
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
	legacy := run(t, in, old)
	if legacy.PolicyVersion == out.PolicyVersion {
		t.Fatal("existing-cap policy reused the primary-only fingerprint")
	}
	if _, has := guardRecommendation(legacy.Results[1], SettingLimits); has {
		t.Fatal("legacy reader generated cap advice")
	}
}
