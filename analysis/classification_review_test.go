// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func TestClassificationThrottlingOnlyReleaseInference(t *testing.T) {
	for _, counter := range []string{"seconds", "throttled-periods", "periods"} {
		t.Run(counter, func(t *testing.T) {
			in := fixture(3600, 60)
			s := counterFixture(in, []float64{0, 120, 240})
			for i := range s.Samples {
				s.Samples[i].Timestamp += 60_000
			}
			c := &in.Containers[0]
			c.CPU.Series, c.Memory.Series = nil, nil
			c.Identity.ReleaseStartedAt = 0
			c.Classification = &ClassificationObservation{}
			switch counter {
			case "seconds":
				c.Classification.Throttling.Seconds = []Series{s}
			case "throttled-periods":
				c.Classification.Throttling.ThrottledPeriods = []Series{s}
			case "periods":
				c.Classification.Throttling.Periods = []Series{s}
			}
			original, _ := json.Marshal(in)
			before := run(t, in, DefaultPolicy())
			p := DefaultPolicy()
			p.Classification = &ClassificationPolicy{}
			after := run(t, in, p)
			result := after.Classifications[0]
			if result.WindowStart != s.Samples[0].Timestamp {
				t.Fatalf("throttling did not establish the release boundary: %+v", result)
			}
			if counter != "periods" && finding(result, FeatureCPUThrottled).Status != ClassificationDetected {
				t.Fatal("positive throttling-only evidence was ignored")
			}
			for _, feature := range []WorkloadFeature{FeatureHighVarianceCPU, FeatureHighVarianceMemory} {
				if finding(result, feature).Status != ClassificationInsufficient {
					t.Fatal("throttling counters became usage evidence")
				}
			}
			if !reflect.DeepEqual(before.Results, after.Results) {
				t.Fatal("classification-only release inference changed sizing")
			}
			encoded, _ := json.Marshal(in)
			if string(encoded) != string(original) {
				t.Fatal("classification mutated the input")
			}
		})
	}
}

func TestClassificationThrottlingEstablishesRollbackCutoff(t *testing.T) {
	for _, counter := range []string{"seconds", "throttled-periods", "periods"} {
		t.Run(counter, func(t *testing.T) {
			in := fixture(3600, 60)
			current := counterFixture(in, []float64{0, 120, 120, 120})
			current.Samples[2].Timestamp = epoch + 31*60_000
			current.Samples[3].Timestamp = epoch + 32*60_000
			other := current
			other.Release = "B"
			other.Samples = []Sample{{Timestamp: epoch + 30*60_000, Value: 0}}
			obs := CPUThrottlingObservation{Seconds: []Series{current}}
			switch counter {
			case "seconds":
				obs.Seconds = append(obs.Seconds, other)
			case "throttled-periods":
				obs.ThrottledPeriods = []Series{other}
			case "periods":
				obs.Periods = []Series{other}
			}
			in.Containers[0].Identity.ReleaseStartedAt = 0
			in.Containers[0].Classification = &ClassificationObservation{Throttling: obs}
			before := run(t, in, DefaultPolicy())
			p := DefaultPolicy()
			p.Classification = &ClassificationPolicy{}
			after := run(t, in, p)
			result := after.Classifications[0]
			f := finding(result, FeatureCPUThrottled)
			if result.WindowStart != epoch+31*60_000 || f.Status != ClassificationNotDetected || len(f.Throttling) != 1 {
				t.Fatalf("pre-rollback throttling was included: %+v", result)
			}
			if *f.Throttling[0].ThrottledSeconds != 0 || f.Throttling[0].ObservedSeconds != 60 {
				t.Fatalf("incorrect post-rollback evidence: %+v", f.Throttling[0])
			}
			if !reflect.DeepEqual(before.Results, after.Results) {
				t.Fatal("classification rollback inference changed sizing")
			}
		})
	}
}

func TestClassificationVarianceCounterWarmupMatchesGauge(t *testing.T) {
	for _, releaseOffset := range []int64{0, 120} {
		t.Run(fmt.Sprint(releaseOffset), func(t *testing.T) {
			in := fixture(35*60+releaseOffset, 60)
			in.Containers[0].Identity.ReleaseStartedAt += releaseOffset * 1000
			s := &in.Containers[0].CPU.Series[0]
			for i := range s.Samples {
				s.Samples[i].Value = 100
				if i%2 == 1 {
					s.Samples[i].Value = 1000
				}
			}
			gauge := finding(classified(t, in), FeatureHighVarianceCPU)
			counter := *s
			counter.Kind = SampleCPUCounterSeconds
			counter.Samples = append([]Sample(nil), s.Samples...)
			cumulative := 0.0
			for i := range counter.Samples {
				if i > 0 {
					cumulative += s.Samples[i].Value / 1000 * 60
				}
				counter.Samples[i].Value = cumulative
			}
			// Source order and samples outside the selected release must not
			// shift the five-minute warmup boundary.
			counter.Samples = append(counter.Samples, Sample{Timestamp: in.WindowStart - 60_000})
			slices.Reverse(counter.Samples)
			*s = counter
			got := finding(classified(t, in), FeatureHighVarianceCPU)
			if gauge.Status != ClassificationDetected || got.Status != ClassificationDetected || !reflect.DeepEqual(got.Variance, gauge.Variance) {
				t.Fatalf("equivalent usage classified differently: gauge=%+v counter=%+v", gauge, got)
			}
		})
	}
}

func TestClassificationThrottlingOptionalPodUID(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("known-uids-%03b", mask), func(t *testing.T) {
			in := fixture(3600, 60)
			rows := []Series{counterFixture(in, []float64{0, 120, 240}), counterFixture(in, []float64{0, 60, 120}), counterFixture(in, []float64{0, 100, 200})}
			wantUID := ""
			for i := range rows {
				if mask&(1<<i) == 0 {
					rows[i].PodUID = ""
				} else {
					wantUID = rows[i].PodUID
				}
			}
			in.Containers[0].Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Seconds: rows[:1], ThrottledPeriods: rows[1:2], Periods: rows[2:]}}
			f := finding(classified(t, in), FeatureCPUThrottled)
			if f.Status != ClassificationDetected || len(f.Throttling) != 1 || f.Throttling[0].PodUID != wantUID || *f.Throttling[0].SecondsPerSecond != 2 || *f.Throttling[0].ThrottledPeriodPercent != 60 {
				t.Fatalf("optional UID changed counter attribution: %+v", f)
			}
		})
	}
	for _, uids := range [][3]string{{"pod-1", "pod-2", ""}, {"pod-1", "", "pod-2"}, {"", "pod-1", "pod-2"}} {
		t.Run(fmt.Sprint(uids), func(t *testing.T) {
			in := fixture(3600, 60)
			rows := []Series{counterFixture(in, []float64{0, 1}), counterFixture(in, []float64{0, 1}), counterFixture(in, []float64{0, 1})}
			for i := range rows {
				rows[i].PodUID = uids[i]
			}
			in.Containers[0].Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Seconds: rows[:1], ThrottledPeriods: rows[1:2], Periods: rows[2:]}}
			p := DefaultPolicy()
			p.Classification = &ClassificationPolicy{}
			if _, err := Analyze(in, p); err == nil {
				t.Fatal("conflicting nonempty Pod UIDs were accepted")
			}
		})
	}
}
