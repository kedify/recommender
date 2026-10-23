// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"math"
	"testing"
)

func TestUsageCoverageToleratesTimestampJitter(t *testing.T) {
	for _, counter := range []bool{false, true} {
		name := "gauge"
		if counter {
			name = "CPU counter"
		}
		t.Run(name, func(t *testing.T) {
			in := jitteredUsageFixture(counter)
			for _, result := range run(t, in, DefaultPolicy()).Results {
				if has(result.DataQuality, ReasonSparseCoverage) || len(result.Recommendations) == 0 {
					t.Fatalf("timestamp jitter blocked sizing: %+v", result)
				}
				if result.DataQuality.Coverage < .9 || result.DataQuality.Coverage > 1 {
					t.Fatalf("unexpected jitter coverage: %+v", result.DataQuality)
				}
				// The series supplying the sizing value uses the same tolerance as
				// release-wide coverage; its confidence must not retain the old penalty.
				if result.Recommendations[0].Confidence < 90 || result.Recommendations[0].Confidence > 95 {
					t.Fatalf("timestamp jitter incorrectly penalized confidence: %+v", result.Recommendations)
				}
				if result.Resource == ResourceCPU && counter && math.Abs(result.Evidence.AggregatedUsage.Value-200) > 1e-7 {
					t.Fatalf("jitter tolerance changed CPU conversion: %+v", result.Evidence.AggregatedUsage)
				}
				if result.Resource == ResourceMemory && result.Evidence.AggregatedUsage.Value != 20*1024*1024 {
					t.Fatalf("jitter tolerance changed memory aggregation: %+v", result.Evidence.AggregatedUsage)
				}
			}
		})
	}
}

func TestUsageCoverageJitterTolerancePreservesOutages(t *testing.T) {
	in := jitteredUsageFixture(false)
	for _, obs := range []*ResourceObservation{&in.Containers[0].CPU, &in.Containers[0].Memory} {
		samples := obs.Series[0].Samples
		obs.Series[0].Samples = append(samples[:40:40], samples[76:]...)
	}
	policy := DefaultPolicy()
	policy.Evidence.MinimumCoverage = .8
	for _, result := range run(t, in, policy).Results {
		if !has(result.DataQuality, ReasonSparseCoverage) || result.DataQuality.Coverage >= .8 || len(result.Recommendations) != 0 {
			t.Fatalf("jitter tolerance concealed a sustained outage: %+v", result)
		}
	}
}

func jitteredUsageFixture(counter bool) Input {
	in := fixture(3840, 32)
	for resourceIndex, obs := range []*ResourceObservation{&in.Containers[0].CPU, &in.Containers[0].Memory} {
		if resourceIndex == 0 && counter {
			obs.Series[0].Kind = SampleCPUCounterSeconds
		}
		for i := range obs.Series[0].Samples {
			// Gaps of 20, 32, and 44 seconds average 32 seconds. Capping
			// every gap at the median incorrectly reports less than 90% coverage.
			seconds := int64(i/3)*96 + [...]int64{0, 20, 52}[i%3]
			obs.Series[0].Samples[i].Timestamp = epoch + seconds*1000
			if resourceIndex == 0 && counter {
				obs.Series[0].Samples[i].Value = float64(seconds) * .2
			}
		}
	}
	return in
}
