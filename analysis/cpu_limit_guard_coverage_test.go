// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func guardStrictPolicy() Policy {
	p := guardTestPolicy()
	p.CPU.LimitReductionGuard.RequireCompleteCoverage = true
	return p
}

func guardFamily(id, pod string, values []float64) Series {
	s := guardCounter(id, "A", epoch, values)
	s.PodUID = pod
	return s
}

// guardCoverageInput gives every usage lifetime a unique PodUID, a complete
// fresh inventory, and one aligned CFS lifetime per Pod in all three families.
func guardCoverageInput(throttled []float64) Input {
	in := fixture(600, 60)
	in.Containers = append([]ContainerObservation(nil), in.Containers...)
	c := &in.Containers[0]
	c.CPU.Series = append([]Series(nil), c.CPU.Series...)
	obs := CPUThrottlingObservation{SourceComplete: true}
	for i := range c.CPU.Series {
		pod := fmt.Sprintf("pod-%d", i+1)
		c.CPU.Series[i].PodUID = pod
		obs.Periods = append(obs.Periods, guardFamily("rt-"+pod, pod, guardRamp(11, 100)))
		obs.ThrottledPeriods = append(obs.ThrottledPeriods, guardFamily("rt-"+pod, pod, append([]float64(nil), throttled...)))
		obs.Seconds = append(obs.Seconds, guardFamily("rt-"+pod, pod, make([]float64, 11)))
	}
	n := len(c.CPU.Series)
	c.Inventory = Inventory{Available: true, Timestamp: in.EvaluationTime, Eligible: n, Observed: n}
	c.Classification = &ClassificationObservation{Throttling: obs}
	return in
}

func guardCFS(in *Input) *CPUThrottlingObservation {
	return &in.Containers[0].Classification.Throttling
}

func guardHasReason(reasons []Reason, r Reason) bool {
	for _, v := range reasons {
		if v == r {
			return true
		}
	}
	return false
}

func TestCPULimitGuardCoverageIsBackwardCompatible(t *testing.T) {
	legacy := guardTestPolicy()
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "requireCompleteCoverage") {
		t.Fatalf("legacy guard policy JSON gained the strict field: %s", encoded)
	}
	if encoded, err = json.Marshal(CPUThrottlingObservation{}); err != nil || strings.Contains(string(encoded), "sourceComplete") {
		t.Fatalf("legacy throttling JSON gained the completeness field: %s %v", encoded, err)
	}
	loose, err := NormalizePolicy(legacy)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := NormalizePolicy(guardStrictPolicy())
	if err != nil || normalizedPolicyVersion(strict) == normalizedPolicyVersion(loose) {
		t.Fatalf("strict coverage did not change the policy version: %v", err)
	}
	complete := guardCoverageInput(guardRamp(11, 5))
	partial := guardCoverageInput(guardRamp(11, 5))
	partial.Containers[0].Classification.Throttling.SourceComplete = false
	got, want := run(t, complete, legacy), run(t, partial, legacy)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("source completeness changed the legacy opt-in guard")
	}
	cpu := got.Results[1]
	if !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPUThrottlingPressure}) {
		t.Fatalf("legacy repeated pressure not preserved: %+v", cpu)
	}
	if _, ok := guardStep(guardSettingTrace(cpu, SettingLimits), ruleCPUThrottlingCoverage); ok {
		t.Fatal("legacy guard evaluated strict coverage")
	}
}

func TestCPULimitGuardStrictCoverageAllowsProvenReduction(t *testing.T) {
	cpu := run(t, guardCoverageInput(make([]float64, 11)), guardStrictPolicy()).Results[1]
	if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
		t.Fatalf("proven complete coverage held the reduction: %+v", cpu)
	}
	lt := guardSettingTrace(cpu, SettingLimits)
	if step, ok := guardStep(lt, ruleCPUThrottlingCoverage); !ok || step.Passed == nil || !*step.Passed {
		t.Fatalf("coverage proof not traced as passed: %+v", lt)
	}
	if step, ok := guardStep(lt, ruleCPURecurringDemand); !ok || step.Passed == nil || !*step.Passed {
		t.Fatalf("demand not assessed independently: %+v", lt)
	}
	if _, ok := guardStep(lt, ruleCPUQuotaPressure); ok {
		t.Fatalf("observed zero throttling produced a pressure verdict: %+v", lt)
	}
	step, ok := guardStep(lt, ruleCPUQuotaMeasuredZero)
	if !ok || step.Passed != nil || step.Values["spanPeriods"] <= 0 || step.Values["spanThrottledPeriods"] != 0 {
		t.Fatalf("measured zero and its denominator were not preserved: %+v", lt)
	}
	if _, ok := guardStep(lt, ruleCPUQuotaPressureUnproven); ok {
		t.Fatalf("proved coverage also reported unknown pressure: %+v", lt)
	}
}

func TestCPULimitGuardStrictCoveragePreservesPressure(t *testing.T) {
	cpu := run(t, guardCoverageInput(guardRamp(11, 5)), guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPUThrottlingPressure}) {
		t.Fatalf("proven repeated pressure not held as pressure: %+v", cpu)
	}
	if step, ok := guardStep(guardSettingTrace(cpu, SettingLimits), ruleCPUThrottlingCoverage); !ok || step.Passed == nil || !*step.Passed {
		t.Fatalf("pressure with full coverage misreported as missing evidence: %+v", step)
	}
}

func TestCPULimitGuardStrictCoverageHoldsWithoutProof(t *testing.T) {
	base := run(t, guardCoverageInput(make([]float64, 11)), guardStrictPolicy()).Results[1]
	baseRequest, _ := guardRecommendation(base, SettingRequests)
	for _, test := range []struct {
		name          string
		mutate        func(*Input, *Policy)
		coverage      bool
		demandUnknown bool
	}{
		{"absent", func(in *Input, _ *Policy) { in.Containers[0].Classification = nil }, false, false},
		{"partial-source", func(in *Input, _ *Policy) { guardCFS(in).SourceComplete = false }, false, false},
		{"zero-denominator", func(in *Input, _ *Policy) {
			o := guardCFS(in)
			o.Periods[0] = guardFamily(o.Periods[0].ID, o.Periods[0].PodUID, make([]float64, 11))
		}, false, false},
		{"throttled-exceeds-total", func(in *Input, _ *Policy) {
			o := guardCFS(in)
			o.ThrottledPeriods[0] = guardFamily(o.ThrottledPeriods[0].ID, o.ThrottledPeriods[0].PodUID, guardRamp(11, 200))
		}, false, false},
		{"wrong-lifetime", func(in *Input, _ *Policy) { guardCFS(in).Seconds[0].ID = "rt-other" }, false, false},
		{"inconsistent-pod", func(in *Input, _ *Policy) { guardCFS(in).ThrottledPeriods[0].PodUID = "pod-other" }, false, false},
		{"overlapping-runtime", func(in *Input, _ *Policy) {
			o := guardCFS(in)
			o.Periods = append(o.Periods, guardFamily("rt-restarted", o.Periods[0].PodUID, guardRamp(11, 100)))
		}, false, false},
		{"missing-pod-cfs", func(in *Input, _ *Policy) {
			o := guardCFS(in)
			o.Periods, o.ThrottledPeriods, o.Seconds = o.Periods[1:], o.ThrottledPeriods[1:], o.Seconds[1:]
		}, false, false},
		{"reset-at-latest-sample", func(in *Input, _ *Policy) {
			guardCFS(in).Periods[0].Samples[10].Value = 0
		}, false, false},
		{"reset-inside-span", func(in *Input, _ *Policy) { guardCFS(in).Periods[0].Samples[9].Value = 0 }, false, false},
		{"misaligned", func(in *Input, _ *Policy) {
			s := &guardCFS(in).ThrottledPeriods[0]
			s.Samples = append(s.Samples[:9:9], s.Samples[10:]...)
		}, false, false},
		{"missing-demand", func(_ *Input, p *Policy) { p.CPU.LimitReductionGuard.RecurringSamples = 1000 }, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			in, p := guardCoverageInput(make([]float64, 11)), guardStrictPolicy()
			test.mutate(&in, &p)
			cpu := run(t, in, p).Results[1]
			if _, ok := guardRecommendation(cpu, SettingLimits); ok || !guardHasReason(cpu.Notices, ReasonCPULimitEvidenceIncomplete) {
				t.Fatalf("unproven evidence did not hold the reduction: %+v", cpu)
			}
			if request, ok := guardRecommendation(cpu, SettingRequests); !ok || request != baseRequest {
				t.Fatalf("request advice changed: %+v", cpu)
			}
			lt := guardSettingTrace(cpu, SettingLimits)
			if step, ok := guardStep(lt, ruleCPUThrottlingCoverage); !ok || step.Passed == nil || *step.Passed != test.coverage {
				t.Fatalf("coverage trace: %+v", lt)
			}
			if step, ok := guardStep(lt, ruleCPURecurringDemandUnknown); ok != test.demandUnknown || ok && (step.Passed == nil || *step.Passed) {
				t.Fatalf("demand trace: %+v", lt)
			}
		})
	}
}

func TestCPUThrottlingCoverageRequiresValidatedExpectedSet(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Input)
		proven bool
	}{
		{"control", func(*Input) {}, true},
		{"inventory-unavailable", func(in *Input) { in.Containers[0].Inventory.Available = false }, false},
		{"stale-inventory", func(in *Input) { in.Containers[0].Inventory.Timestamp = in.EvaluationTime - 3600000 }, false},
		{"future-inventory", func(in *Input) { in.Containers[0].Inventory.Timestamp = in.EvaluationTime + 1000 }, false},
		{"excluded-pod", func(in *Input) { in.Containers[0].Inventory.Excluded = 1 }, false},
		{"unobserved-pod", func(in *Input) { in.Containers[0].Inventory.Eligible++; in.Containers[0].Inventory.Observed++ }, false},
		{"partial-observed", func(in *Input) { in.Containers[0].Inventory.Observed-- }, false},
		{"unidentified-usage", func(in *Input) { in.Containers[0].CPU.Series[0].PodUID = "" }, false},
		{"duplicate-usage-pod", func(in *Input) {
			c := &in.Containers[0]
			c.CPU.Series = append(c.CPU.Series, c.CPU.Series[0])
		}, false},
		{"stale-counters", func(in *Input) {
			o := guardCFS(in)
			id, pod := o.Periods[0].ID, o.Periods[0].PodUID
			o.Periods[0] = guardFamily(id, pod, guardRamp(5, 100))
			o.ThrottledPeriods[0] = guardFamily(id, pod, make([]float64, 5))
			o.Seconds[0] = guardFamily(id, pod, make([]float64, 5))
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := guardCoverageInput(make([]float64, 11))
			test.mutate(&in)
			c := in.Containers[0]
			if got := cpuThrottlingCoverage(in, c, c.CPU, 120); got.proven != test.proven {
				t.Fatalf("coverage proof %v, want %v: %+v", got.proven, test.proven, got)
			}
		})
	}
}

func TestStrictCPUDemandRequiresEveryPod(t *testing.T) {
	in := guardCoverageInput(make([]float64, 11))
	c := &in.Containers[0]
	short := c.CPU.Series[0]
	short.ID, short.PodUID = "short", "pod-short"
	short.Samples = short.Samples[len(short.Samples)-2:]
	c.CPU.Series = append(c.CPU.Series, short)
	c.Inventory.Eligible, c.Inventory.Observed = 2, 2
	counter := guardCFS(&in)
	counter.Periods = append(counter.Periods, guardFamily("rt-short", short.PodUID, guardRamp(11, 100)))
	counter.ThrottledPeriods = append(counter.ThrottledPeriods, guardFamily("rt-short", short.PodUID, make([]float64, 11)))
	counter.Seconds = append(counter.Seconds, guardFamily("rt-short", short.PodUID, make([]float64, 11)))
	cpu := run(t, in, guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !guardHasReason(cpu.Notices, ReasonCPULimitEvidenceIncomplete) {
		t.Fatalf("another Pod's samples must not supply recurring demand: %+v", cpu)
	}
}

func TestStrictCPUCoverageIgnoresStaleRuntimeAndUsesSnapshot(t *testing.T) {
	for _, withSnapshot := range []bool{false, true} {
		in := guardCoverageInput(make([]float64, 11))
		counter := guardCFS(&in)
		old := guardFamily("previous-runtime", counter.Periods[0].PodUID, guardRamp(11, 100))
		old.Samples = old.Samples[:4]
		if withSnapshot {
			counter.CoverageAt = in.EvaluationTime
			old.Samples = guardFamily("previous-runtime", old.PodUID, guardRamp(11, 100)).Samples[:10]
		}
		counter.Periods = append(counter.Periods, old)
		cpu := run(t, in, guardStrictPolicy()).Results[1]
		if _, ok := guardRecommendation(cpu, SettingLimits); !ok {
			t.Fatalf("withSnapshot=%t: historical counter held proven reduction: %+v", withSnapshot, cpu)
		}
	}
}

func TestStrictCPUCoverageUsesCurrentSegmentAfterRollback(t *testing.T) {
	in := guardCoverageInput(make([]float64, 11))
	counter := guardCFS(&in)
	// Prior A pressure is still fresh, yet a B counter proves the latest A
	// segment starts later. Current A has enough aligned intervals.
	for i := range counter.ThrottledPeriods[0].Samples {
		counter.ThrottledPeriods[0].Samples[i].Value = float64(min(i, 3)) * 10
	}
	other := guardFamily("intervening", "other-pod", guardRamp(11, 100))
	other.Release = "B"
	other.Samples = other.Samples[6:7]
	counter.Periods = append(counter.Periods, other)
	strict := run(t, in, guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(strict, SettingLimits); !ok {
		t.Fatalf("old A pressure affected the new A segment: %+v", strict)
	}
	legacy := run(t, in, guardTestPolicy()).Results[1]
	if !guardHasReason(legacy.Notices, ReasonCPUThrottlingPressure) {
		t.Fatalf("legacy pressure evidence changed: %+v", legacy)
	}
	in.Containers[0].Inventory.Timestamp = epoch + 6*60_000
	strict = run(t, in, guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(strict, SettingLimits); ok || !guardHasReason(strict.Notices, ReasonCPULimitEvidenceIncomplete) {
		t.Fatalf("inventory from before the current segment authorized reduction: %+v", strict)
	}
}

func TestStrictCPUCoverageRequiresLatestSnapshotForEveryFamily(t *testing.T) {
	in := guardCoverageInput(make([]float64, 11))
	counter := guardCFS(&in)
	counter.CoverageAt = in.EvaluationTime
	counter.Seconds[0].Samples = counter.Seconds[0].Samples[:10]
	cpu := run(t, in, guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !guardHasReason(cpu.Notices, ReasonCPULimitEvidenceIncomplete) {
		t.Fatalf("an earlier counter row certified current coverage: %+v", cpu)
	}
}

func TestStrictCPUCoverageCannotUseAdvisoryRuntime(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		historicalOnly, currentOnly bool
		want                        bool
	}{
		{name: "unmarked fresh history is ambiguous"},
		{name: "advisory history cannot certify but valid current data can", historicalOnly: true, want: true},
		{name: "advisory current runtime leaves proof incomplete", historicalOnly: true, currentOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := guardCoverageInput(make([]float64, 11))
			c := &in.Containers[0]
			historicalUsage := c.CPU.Series[0]
			historicalUsage.ID = "previous-usage"
			historicalUsage.Samples = historicalUsage.Samples[:9]
			historicalUsage.CPUGuardAdvisoryOnly = tc.historicalOnly
			c.CPU.Series = append(c.CPU.Series, historicalUsage)
			counter := guardCFS(&in)
			for _, family := range []*[]Series{&counter.Periods, &counter.ThrottledPeriods, &counter.Seconds} {
				historical := (*family)[0]
				historical.ID = "previous-runtime"
				historical.Samples = historical.Samples[:9]
				historical.CPUGuardAdvisoryOnly = tc.historicalOnly
				*family = append(*family, historical)
			}
			counter.Periods[0].CPUGuardAdvisoryOnly = tc.currentOnly
			cpu := run(t, in, guardStrictPolicy()).Results[1]
			_, proposed := guardRecommendation(cpu, SettingLimits)
			if proposed != tc.want || !tc.want && !guardHasReason(cpu.Notices, ReasonCPULimitEvidenceIncomplete) {
				t.Fatalf("finite reduction = %t, want %t: %+v", proposed, tc.want, cpu)
			}
		})
	}
}
