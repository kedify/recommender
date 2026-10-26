// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"math"
	"testing"
)

func TestVarianceEvidenceReportsClassifierPopulationStatistics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		feature WorkloadFeature
		scale   float64
		counter bool
		withGap bool
	}{
		{name: "cpu", feature: FeatureHighVarianceCPU, scale: 1},
		{name: "memory", feature: FeatureHighVarianceMemory, scale: 1024 * 1024},
		{name: "cpu counter", feature: FeatureHighVarianceCPU, scale: 1, counter: true},
		{name: "cpu with gap", feature: FeatureHighVarianceCPU, scale: 1, withGap: true},
		{name: "memory with gap", feature: FeatureHighVarianceMemory, scale: 1024 * 1024, withGap: true},
		{name: "cpu counter with gap", feature: FeatureHighVarianceCPU, scale: 1, counter: true, withGap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture(3600, 60)
			series := in.Containers[0].CPU.Series[0]
			series.Samples = nil
			// Warmup outliers must not affect the reported population statistics.
			for sec := int64(0); sec <= 300; sec += 60 {
				series.Samples = append(series.Samples, Sample{Timestamp: epoch + sec*1000, Value: 10_000 * tc.scale})
			}
			at := epoch + 300_000
			for i := 0; i < 30; i++ {
				if tc.withGap && i == 15 {
					at += 300_000
					series.Samples = append(series.Samples, Sample{Timestamp: at, Value: 10_000 * tc.scale})
				}
				at += 30_000
				series.Samples = append(series.Samples, Sample{Timestamp: at, Value: 100 * tc.scale})
				at += 60_000
				series.Samples = append(series.Samples, Sample{Timestamp: at, Value: 700 * tc.scale})
			}
			if tc.counter {
				series.Kind = SampleCPUCounterSeconds
				total := 0.0
				for i := range series.Samples {
					if i > 0 {
						total += series.Samples[i].Value * float64(series.Samples[i].Timestamp-series.Samples[i-1].Timestamp) / 1_000_000
					}
					series.Samples[i].Value = total
				}
			}
			in.EvaluationTime = at
			in.Containers[0].Identity.Timestamp = at
			if tc.feature == FeatureHighVarianceMemory {
				in.Containers[0].Memory.Series = []Series{series}
			} else {
				in.Containers[0].CPU.Series = []Series{series}
			}
			result := finding(classified(t, in), tc.feature)
			if result.Status != ClassificationDetected || len(result.Variance) != 1 {
				t.Fatalf("expected one detected lifetime: %+v", result)
			}
			evidence := result.Variance[0]
			// The 700-valued samples cover twice the duration of the 100-valued
			// samples: mean=500, population variance=80,000, independent of gaps.
			assertVarianceStatistic(t, "mean", evidence.Mean, 500*tc.scale)
			assertVarianceStatistic(t, "variance", evidence.Variance, 80_000*tc.scale*tc.scale)
			assertVarianceStatistic(t, "standard deviation", evidence.StandardDeviation, math.Sqrt(80_000)*tc.scale)
			assertVarianceStatistic(t, "coefficient", evidence.CoefficientOfVariation, evidence.StandardDeviation/evidence.Mean)
			if evidence.ObservedStart != epoch+300_000 {
				t.Fatalf("wrong warmup boundary: %d", evidence.ObservedStart)
			}
		})
	}
}

func TestVarianceEvidenceIncludesZeroStatisticsInJSON(t *testing.T) {
	in := fixture(3600, 20)
	for i := range in.Containers[0].CPU.Series[0].Samples {
		in.Containers[0].CPU.Series[0].Samples[i].Value = 0
	}
	result := finding(classified(t, in), FeatureHighVarianceCPU)
	if result.Status != ClassificationNotDetected || len(result.Variance) != 1 {
		t.Fatalf("zero-valued usage did not retain evaluated evidence: %+v", result)
	}
	encoded, err := json.Marshal(result.Variance[0])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"mean", "standardDeviation", "variance"} {
		value, ok := raw[key]
		if !ok {
			t.Fatalf("missing zero-valued %s in %s", key, encoded)
		}
		var statistic float64
		if err := json.Unmarshal(value, &statistic); err != nil {
			t.Fatal(err)
		}
		if statistic != 0 {
			t.Fatalf("%s = %v, want zero", key, statistic)
		}
	}
}

func assertVarianceStatistic(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > math.Max(1, math.Abs(want))*1e-10 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
