// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"reflect"
	"testing"
)

func TestCPULimitGuardOneOffIncrementsDoNotHold(t *testing.T) {
	oneOff := func(id string) Series {
		return guardCounter(id, "A", epoch, []float64{0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 5})
	}
	for _, test := range []struct {
		name   string
		series []Series
	}{
		{"single-increment", []Series{oneOff("pod-1")}},
		{"one-increment-per-lifetime", []Series{oneOff("pod-1"), oneOff("pod-2")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := guardWithThrottling(fixture(600, 60), CPUThrottlingObservation{ThrottledPeriods: test.series})
			cpu := run(t, in, guardTestPolicy()).Results[1]
			if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
				t.Fatalf("isolated increment held the limit: %+v", cpu)
			}
			step, ok := guardStep(guardSettingTrace(cpu, SettingLimits), ruleCPUQuotaPressureUnproven)
			if !ok || step.Passed != nil {
				t.Fatalf("isolated increment must be traced descriptively, not as a passed check: %+v", step)
			}
		})
	}
	twice := guardCounter("pod-1", "A", epoch, []float64{0, 0, 0, 5, 5, 5, 5, 10, 10, 10, 10})
	cpu := run(t, guardWithThrottling(fixture(600, 60), CPUThrottlingObservation{ThrottledPeriods: []Series{twice}}), guardTestPolicy()).Results[1]
	if _, ok := guardRecommendation(cpu, SettingLimits); ok || !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPUThrottlingPressure}) {
		t.Fatalf("two positive intervals in one lifetime did not hold: %+v", cpu)
	}
}

func TestCPULimitGuardStaleCountersDoNotHold(t *testing.T) {
	// Repeated pressure that ends 360s before evaluation.
	in := guardWithThrottling(fixture(600, 60), CPUThrottlingObservation{ThrottledPeriods: []Series{guardCounter("pod-1", "A", epoch, guardRamp(5, 5))}})
	p := guardTestPolicy()
	p.Evidence.FreshnessSeconds = 3600
	if cpu := run(t, in, p).Results[1]; !reflect.DeepEqual(cpu.Notices, []Reason{ReasonCPUThrottlingPressure}) {
		t.Fatalf("control: fresh repeated pressure not held: %+v", cpu)
	}
	p.Evidence.FreshnessSeconds = 120
	cpu := run(t, in, p).Results[1]
	if limit, ok := guardRecommendation(cpu, SettingLimits); !ok || limit.SuggestedValue != 150 || len(cpu.Notices) != 0 {
		t.Fatalf("stale counters held the limit: %+v", cpu)
	}
	lt := guardSettingTrace(cpu, SettingLimits)
	if step, ok := guardStep(lt, ruleCPUQuotaPressureUnknown); !ok || step.Passed != nil {
		t.Fatalf("stale counters must be traced as unknown, not a passed check: %+v", lt)
	}
	if _, ok := guardStep(lt, ruleCPUQuotaPressure); ok {
		t.Fatalf("stale counters produced a quota pressure verdict: %+v", lt)
	}
}
