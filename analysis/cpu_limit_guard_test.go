// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func guardTestPolicy() Policy {
	p := shortPolicy()
	p.CPU.LimitReductionGuard = &CPULimitReductionGuardPolicy{}
	return p
}

func guardCounter(id, release string, start int64, values []float64) Series {
	s := Series{ID: id, PodUID: id, WorkloadUID: "uid", Release: release, Kind: SampleGauge}
	for i, v := range values {
		s.Samples = append(s.Samples, Sample{Timestamp: start + int64(i)*60000, Value: v})
	}
	return s
}

func guardRamp(n int, step float64) []float64 {
	values := make([]float64, n)
	for i := range values {
		values[i] = float64(i) * step
	}
	return values
}

func guardWithThrottling(in Input, obs CPUThrottlingObservation) Input {
	in.Containers = append([]ContainerObservation(nil), in.Containers...)
	in.Containers[0].Classification = &ClassificationObservation{Throttling: obs}
	return in
}

func guardSettingTrace(r ResourceAnalysis, setting Setting) SettingTrace {
	for _, s := range r.DecisionTrace.Settings {
		if s.Setting == setting {
			return s
		}
	}
	return SettingTrace{}
}

func guardRecommendation(r ResourceAnalysis, setting Setting) (Recommendation, bool) {
	for _, rec := range r.Recommendations {
		if rec.Setting == setting {
			return rec, true
		}
	}
	return Recommendation{}, false
}

func guardStep(t SettingTrace, rule string) (DecisionStep, bool) {
	for _, s := range t.Steps {
		if s.Rule == rule {
			return s, true
		}
	}
	return DecisionStep{}, false
}

func guardPressure() Series { return guardCounter("pod-1", "A", epoch, guardRamp(11, 5)) }

func TestCPULimitGuardIsOptInAndPolicyCompatible(t *testing.T) {
	encoded, err := json.Marshal(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "limitReductionGuard") {
		t.Fatalf("default policy JSON gained a guard field: %s", encoded)
	}
	var decoded Policy
	if err = json.Unmarshal(encoded, &decoded); err != nil || decoded.CPU.LimitReductionGuard != nil {
		t.Fatalf("original policy JSON activated the guard: %+v %v", decoded.CPU, err)
	}
	original, _ := PolicyVersion(Policy{})
	if replayed, err := PolicyVersion(decoded); err != nil || replayed != original {
		t.Fatalf("original policy version changed: %s %s %v", original, replayed, err)
	}
	requested := Policy{CPU: CPUPolicy{LimitReductionGuard: &CPULimitReductionGuardPolicy{}}}
	normalized, err := NormalizePolicy(requested)
	if err != nil || normalized.CPU.LimitReductionGuard.RecurringSamples != 3 || requested.CPU.LimitReductionGuard.RecurringSamples != 0 {
		t.Fatalf("guard defaults or input immutability: %+v %v", normalized.CPU.LimitReductionGuard, err)
	}
	if normalizedPolicyVersion(normalized) == original {
		t.Fatal("opt-in guard did not change the policy version")
	}
	if _, err = NormalizePolicy(Policy{CPU: CPUPolicy{LimitReductionGuard: &CPULimitReductionGuardPolicy{RecurringSamples: -1}}}); err == nil {
		t.Fatal("negative recurring samples accepted")
	}
	pressured := guardWithThrottling(fixture(600, 60), CPUThrottlingObservation{ThrottledPeriods: []Series{guardPressure()}})
	if !reflect.DeepEqual(run(t, fixture(600, 60), shortPolicy()), run(t, pressured, shortPolicy())) {
		t.Fatal("throttling input changed sizing without the explicit guard")
	}
}

func TestCPULimitGuardHoldsOnlyLimitReductionUnderSameReleasePressure(t *testing.T) {
	for _, counter := range []string{"throttled-periods", "throttled-seconds"} {
		t.Run(counter, func(t *testing.T) {
			obs := CPUThrottlingObservation{ThrottledPeriods: []Series{guardPressure()}}
			if counter == "throttled-seconds" {
				obs = CPUThrottlingObservation{Seconds: []Series{guardPressure()}}
			}
			base := run(t, fixture(600, 60), guardTestPolicy())
			got := run(t, guardWithThrottling(fixture(600, 60), obs), guardTestPolicy())
			if !reflect.DeepEqual(got.Results[0], base.Results[0]) {
				t.Fatalf("memory advice changed: %+v", got.Results[0])
			}
			cpu, baseCPU := got.Results[1], base.Results[1]
			if limit, ok := guardRecommendation(baseCPU, SettingLimits); !ok || limit.SuggestedValue != 150 {
				t.Fatalf("absent counters held the baseline limit: %+v", baseCPU)
			}
			request, ok := guardRecommendation(cpu, SettingRequests)
			baseRequest, _ := guardRecommendation(baseCPU, SettingRequests)
			if !ok || request != baseRequest || len(cpu.Recommendations) != 1 {
				t.Fatalf("independent request advice changed or limit not held: %+v", cpu)
			}
			if request.SuggestedValue > cpu.Evidence.CurrentLimit.Value {
				t.Fatalf("request exceeds retained limit: %+v", cpu)
			}
			lt := guardSettingTrace(cpu, SettingLimits)
			if lt.Disposition != "retained" || !reflect.DeepEqual(lt.Reasons, []Reason{ReasonCPUThrottlingPressure}) || !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPUThrottlingPressure}) {
				t.Fatalf("hold not traced exactly once: %+v %+v", lt, cpu.Notices)
			}
			if !reflect.DeepEqual(cpu.DataQuality, baseCPU.DataQuality) || cpu.NoActionReason != "" {
				t.Fatalf("hold degraded data quality: %+v", cpu)
			}
			if step, ok := guardStep(lt, ruleCPURecurringDemand); !ok || step.Passed == nil || !*step.Passed {
				t.Fatalf("demand check was not evaluated separately: %+v", lt)
			}
		})
	}
	t.Run("no other advice", func(t *testing.T) {
		in := fixture(600, 60)
		in.Containers[0].CPU.CurrentRequest.Value = 30
		in = guardWithThrottling(in, CPUThrottlingObservation{ThrottledPeriods: []Series{guardPressure()}})
		cpu := run(t, in, guardTestPolicy()).Results[1]
		if len(cpu.Recommendations) != 0 || cpu.NoActionReason != ReasonCPUThrottlingPressure || has(cpu.DataQuality, ReasonNoMaterialChange) {
			t.Fatalf("held limit not reported as no-action reason: %+v", cpu)
		}
	})
}

func TestCPULimitGuardHealthyAndAbsentCountersDoNotHold(t *testing.T) {
	for _, test := range []struct {
		name   string
		obs    *CPUThrottlingObservation
		rule   string
		passed bool
	}{
		{"healthy", &CPUThrottlingObservation{ThrottledPeriods: []Series{guardCounter("pod-1", "A", epoch, make([]float64, 11))}}, ruleCPUQuotaPressureUnproven, false},
		{"absent", nil, ruleCPUQuotaPressureUnknown, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := fixture(600, 60)
			if test.obs != nil {
				in = guardWithThrottling(in, *test.obs)
			}
			cpu := run(t, in, guardTestPolicy()).Results[1]
			if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
				t.Fatalf("limit reduction held: %+v", cpu)
			}
			step, ok := guardStep(guardSettingTrace(cpu, SettingLimits), test.rule)
			if !ok || (step.Passed != nil) != test.passed || test.passed && !*step.Passed {
				t.Fatalf("absent counters must not be reported as a passed zero check: %+v", step)
			}
		})
	}
}

func TestCPULimitGuardIgnoresUntrustworthyCounters(t *testing.T) {
	for _, test := range []struct {
		name   string
		series func() []Series
	}{
		{"previous-release", func() []Series { s := guardPressure(); s.Release = "B"; return []Series{s} }},
		{"other-workload", func() []Series { s := guardPressure(); s.WorkloadUID = "other"; return []Series{s} }},
		{"pre-release", func() []Series { return []Series{guardCounter("pod-1", "A", epoch-600000, guardRamp(11, 5))} }},
		{"future", func() []Series { return []Series{guardCounter("pod-1", "A", epoch+660000, guardRamp(11, 5))} }},
		{"malformed", func() []Series { s := guardPressure(); s.Samples[3].Value = math.NaN(); return []Series{s} }},
		{"negative", func() []Series { s := guardPressure(); s.Samples[3].Value = -1; return []Series{s} }},
		{"wrong-kind", func() []Series { s := guardPressure(); s.Kind = SampleCPUCounterSeconds; return []Series{s} }},
		{"missing-id", func() []Series { s := guardPressure(); s.ID = ""; return []Series{s} }},
		{"duplicate-lifetime", func() []Series { return []Series{guardPressure(), guardPressure()} }},
		{"reset-only", func() []Series {
			return []Series{guardCounter("pod-1", "A", epoch, append([]float64{100}, make([]float64, 10)...))}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := guardWithThrottling(fixture(600, 60), CPUThrottlingObservation{ThrottledPeriods: test.series()})
			cpu := run(t, in, guardTestPolicy()).Results[1]
			if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
				t.Fatalf("untrustworthy counters held the limit: %+v", cpu)
			}
		})
	}
}

func TestCPULimitGuardRecurringDemandIsSeparateFromPressure(t *testing.T) {
	for _, spikes := range []int{2, 3} {
		in := fixture(3600, 60)
		s := &in.Containers[0].CPU.Series[0]
		for _, i := range []int{10, 30, 50}[:spikes] {
			s.Samples[i].Value = 200
		}
		cpu := run(t, in, guardTestPolicy()).Results[1]
		if cpu.Evidence.AggregatedUsage.Value != 10 {
			t.Fatalf("spikes changed percentile sizing: %+v", cpu.Evidence)
		}
		if request, ok := guardRecommendation(cpu, SettingRequests); !ok || request.SuggestedValue != 30 {
			t.Fatalf("request advice changed: %+v", cpu)
		}
		lt := guardSettingTrace(cpu, SettingLimits)
		_, limited := guardRecommendation(cpu, SettingLimits)
		if spikes == 3 {
			if limited || lt.Disposition != "retained" || !reflect.DeepEqual(lt.Reasons, []Reason{ReasonCPULimitBelowDemand}) || !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPULimitBelowDemand}) {
				t.Fatalf("recurring demand above cap not held: %+v", cpu)
			}
		} else if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
			t.Fatalf("non-recurring spikes held the limit: %+v", cpu)
		}
	}
}
