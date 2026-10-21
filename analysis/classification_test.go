// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"testing"
)

func classified(t *testing.T, in Input) WorkloadClassification {
	t.Helper()
	p := DefaultPolicy()
	p.Classification = &ClassificationPolicy{}
	return run(t, in, p).Classifications[0]
}
func finding(c WorkloadClassification, feature WorkloadFeature) FeatureFinding {
	for _, f := range c.Findings {
		if f.Feature == feature {
			return f
		}
	}
	return FeatureFinding{}
}
func TestClassificationOptionalAdvisoryAndImmutable(t *testing.T) {
	in := fixture(3600, 20)
	c := &in.Containers[0]
	c.Classification = &ClassificationObservation{OOMKills: []OOMKill{{ID: "kill", PodUID: "pod-1", WorkloadUID: "uid", Release: "A", Timestamp: in.EvaluationTime - 1000, MemoryLimitBytes: 1024 * 1024 * 1024}}}
	original, _ := json.Marshal(in)
	before := run(t, in, DefaultPolicy())
	p := DefaultPolicy()
	p.Classification = &ClassificationPolicy{}
	after := run(t, in, p)
	if !reflect.DeepEqual(before.Results, after.Results) {
		t.Fatal("classification changed sizing")
	}
	if len(before.Classifications) != 0 {
		t.Fatal("classification enabled by input alone")
	}
	if !slices.Contains(after.Classifications[0].Features, FeatureOOMKilled) {
		t.Fatal("classification-only OOM omitted")
	}
	encoded, _ := json.Marshal(in)
	if string(encoded) != string(original) {
		t.Fatal("input mutated")
	}
	var restored Input
	if err := json.Unmarshal(original, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, run(t, restored, p)) {
		t.Fatal("offline input differs")
	}
}
func TestVarianceExampleProfiles(t *testing.T) {
	cpu := []float64{30, 650, 70, 800, 120, 500}
	memory := []float64{10, 150, 20, 300, 40, 240}
	for _, profile := range []string{"cpu", "memory", "both", "stable", "tiny"} {
		t.Run(profile, func(t *testing.T) {
			in := fixture(3600, 20)
			for i := range in.Containers[0].CPU.Series[0].Samples {
				if profile == "cpu" || profile == "both" {
					in.Containers[0].CPU.Series[0].Samples[i].Value = cpu[i%len(cpu)]
				}
				if profile == "tiny" {
					in.Containers[0].CPU.Series[0].Samples[i].Value = cpu[i%len(cpu)] / 1000
				}
			}
			for i := range in.Containers[0].Memory.Series[0].Samples {
				if profile == "memory" || profile == "both" {
					in.Containers[0].Memory.Series[0].Samples[i].Value = memory[i%len(memory)] * 1024 * 1024
				}
			}
			result := classified(t, in)
			if slices.Contains(result.Features, FeatureHighVarianceCPU) != (profile == "cpu" || profile == "both") {
				t.Fatalf("CPU classification: %+v", result.Features)
			}
			if slices.Contains(result.Features, FeatureHighVarianceMemory) != (profile == "memory" || profile == "both") {
				t.Fatalf("memory classification: %+v", result.Features)
			}
		})
	}
}
func TestVarianceDoesNotPoolReplicasAndRejectsSparseHistory(t *testing.T) {
	in := fixture(3600, 20)
	replica := in.Containers[0].CPU.Series[0]
	replica.ID = "other"
	replica.PodUID = "other"
	replica.Samples = append([]Sample(nil), replica.Samples...)
	for i := range replica.Samples {
		replica.Samples[i].Value = 1000
	}
	in.Containers[0].CPU.Series = append(in.Containers[0].CPU.Series, replica)
	if slices.Contains(classified(t, in).Features, FeatureHighVarianceCPU) {
		t.Fatal("replica difference treated as temporal variance")
	}
	in = fixture(1200, 20)
	if finding(classified(t, in), FeatureHighVarianceCPU).Status != ClassificationInsufficient {
		t.Fatal("short history was sufficient")
	}
	in = fixture(3600, 20)
	s := &in.Containers[0].CPU.Series[0]
	kept := []Sample{}
	for i, v := range s.Samples {
		if i < 50 || i > 140 {
			kept = append(kept, v)
		}
	}
	s.Samples = kept
	if finding(classified(t, in), FeatureHighVarianceCPU).Status != ClassificationInsufficient {
		t.Fatal("outage was counted as coverage")
	}
}
func TestClassificationLeaseAndEndpointAttribution(t *testing.T) {
	in := fixture(3600, 20)
	end := in.EvaluationTime
	in.Containers[0].Classification = &ClassificationObservation{
		Leases:    []LeaseObservation{{Namespace: "shop", Name: "leader", WorkloadUID: "uid", PodUID: "pod-1", Timestamp: end - 1000, ExpiresAt: end + 10000}, {Namespace: "other", Name: "wrong", WorkloadUID: "uid", Timestamp: end, ExpiresAt: end + 10000}},
		Endpoints: []EndpointObservation{{Namespace: "shop", Name: "Service/api", WorkloadUID: "uid", Container: "app", Port: 8080, Timestamp: end, HTTP: true}, {Namespace: "shop", Name: "Service/metrics", WorkloadUID: "uid", Container: "sidecar", Port: 9090, Timestamp: end, MetricsVerified: true}},
	}
	result := classified(t, in)
	if !slices.Contains(result.Features, FeatureLeaderElection) || !slices.Contains(result.Features, FeatureHTTPTraffic) || slices.Contains(result.Features, FeatureMetrics) {
		t.Fatalf("attribution: %v", result.Features)
	}
	in.Containers[0].Classification.Endpoints[1].Container = "app"
	if !slices.Contains(classified(t, in).Features, FeatureMetrics) {
		t.Fatal("verified metrics missing")
	}
	in.Containers[0].Classification.Leases[0].ExpiresAt = end - 1
	if slices.Contains(classified(t, in).Features, FeatureLeaderElection) {
		t.Fatal("expired lease accepted")
	}
	in.Containers[0].Identity.Ambiguous = true
	if len(classified(t, in).Features) != 0 {
		t.Fatal("ambiguous identity classified")
	}
}
func counterFixture(in Input, values []float64) Series {
	s := in.Containers[0].CPU.Series[0]
	s.Samples = nil
	for i, value := range values {
		s.Samples = append(s.Samples, Sample{Timestamp: in.WindowStart + int64(i)*60000, Value: value})
	}
	return s
}
func TestThrottlingSeverityAndMissingDenominator(t *testing.T) {
	in := fixture(3600, 20)
	obs := CPUThrottlingObservation{Seconds: []Series{counterFixture(in, []float64{0, 120, 240})}, ThrottledPeriods: []Series{counterFixture(in, []float64{0, 60, 120})}, Periods: []Series{counterFixture(in, []float64{0, 100, 200})}}
	in.Containers[0].Classification = &ClassificationObservation{Throttling: obs}
	f := finding(classified(t, in), FeatureCPUThrottled)
	if f.Status != ClassificationDetected || *f.Throttling[0].SecondsPerSecond != 2 || *f.Throttling[0].ThrottledPeriodPercent != 60 {
		t.Fatalf("severity: %+v", f)
	}
	in.Containers[0].Classification.Throttling.Periods = nil
	f = finding(classified(t, in), FeatureCPUThrottled)
	if f.Throttling[0].ThrottledPeriodPercent != nil || *f.Throttling[0].SecondsPerSecond != 2 {
		t.Fatal("missing denominator invented a percentage")
	}
	in.Containers[0].Classification.Throttling = CPUThrottlingObservation{ThrottledPeriods: obs.ThrottledPeriods}
	if finding(classified(t, in), FeatureCPUThrottled).Status != ClassificationDetected {
		t.Fatal("periods-only evidence ignored")
	}
}
func TestCounterIntervalsResetsDuplicatesGapsAndValidation(t *testing.T) {
	in := fixture(3600, 20)
	s := counterFixture(in, []float64{10, 20, 2, 5})
	intervals, err := CounterIntervals(s, in.WindowStart, in.EvaluationTime)
	if err != nil || len(intervals) != 2 || intervals[1].Delta != 3 {
		t.Fatalf("reset: %+v %v", intervals, err)
	}
	slices.Reverse(s.Samples)
	s.Samples = append(s.Samples, s.Samples[0])
	duplicate, err := CounterIntervals(s, in.WindowStart, in.EvaluationTime)
	if err != nil || !reflect.DeepEqual(intervals, duplicate) {
		t.Fatal("sorting/duplicate handling changed deltas")
	}
	s = counterFixture(in, []float64{0, 1, 2, 3})
	s.Samples[3].Timestamp += 600000
	intervals, err = CounterIntervals(s, in.WindowStart, in.EvaluationTime)
	if err != nil || len(intervals) != 2 {
		t.Fatal("gap included")
	}
	s.Samples[1].Value = math.NaN()
	if _, err = CounterIntervals(s, in.WindowStart, in.EvaluationTime); err == nil {
		t.Fatal("invalid counter accepted")
	}
}
func TestMemoryLeakClassificationReusesDetector(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile func(float64) float64
		want    bool
	}{
		{"retained-memory-example", func(h float64) float64 { return 64 + 12*math.Floor(h*2) }, true},
		{"bounded-gc", func(h float64) float64 { return 128 + 64*math.Mod(h*6, 1) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := leakFixture(24, test.profile)
			result := classified(t, in)
			if slices.Contains(result.Features, FeatureMemoryLeak) != test.want {
				t.Fatalf("leak: %+v", finding(result, FeatureMemoryLeak))
			}
		})
	}
}
func TestClassificationIgnoresPreviousReleaseSignals(t *testing.T) {
	in := fixture(3600, 20)
	old := counterFixture(in, []float64{0, 100, 200})
	old.Release = "old"
	in.Containers[0].Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Seconds: []Series{old}}, OOMKills: []OOMKill{{ID: "old", WorkloadUID: "uid", Release: "old", Timestamp: in.EvaluationTime - 1}}}
	result := classified(t, in)
	if slices.Contains(result.Features, FeatureCPUThrottled) || slices.Contains(result.Features, FeatureOOMKilled) {
		t.Fatal("old release contaminated current tags")
	}
}

func TestClassificationOnlyOOMWithoutUtilization(t *testing.T) {
	in := fixture(3600, 20)
	c := &in.Containers[0]
	c.CPU.Series = nil
	c.Memory.Series = nil
	c.Identity.ReleaseStartedAt = 0
	c.Classification = &ClassificationObservation{OOMKills: []OOMKill{{ID: "oom", WorkloadUID: "uid", Release: "A", Timestamp: in.EvaluationTime - 1000}}}
	result := classified(t, in)
	if !slices.Contains(result.Features, FeatureOOMKilled) {
		t.Fatal("OOM-only container lost its classification")
	}
	if finding(result, FeatureMemoryLeak).Status != ClassificationInsufficient {
		t.Fatal("OOM alone established leak")
	}
}
func TestLeaseObservedSnapshotSurvivesMetricCollectionDelay(t *testing.T) {
	in := fixture(3600, 20)
	end := in.EvaluationTime
	in.Containers[0].Classification = &ClassificationObservation{Leases: []LeaseObservation{{Namespace: "shop", Name: "lease", WorkloadUID: "uid", Timestamp: end - 60000, ObservedAt: end - 30000, ExpiresAt: end - 10000}}}
	if !slices.Contains(classified(t, in).Features, FeatureLeaderElection) {
		t.Fatal("active lease snapshot lost during metric collection")
	}
	in.Containers[0].Classification.Leases[0].ObservedAt = end + 1
	if slices.Contains(classified(t, in).Features, FeatureLeaderElection) {
		t.Fatal("future lease snapshot accepted")
	}
}
func TestUnresolvedEndpointIsEvidenceWithoutTag(t *testing.T) {
	in := fixture(3600, 20)
	in.Containers[0].Classification = &ClassificationObservation{Endpoints: []EndpointObservation{{Namespace: "shop", Name: "Service/unknown", WorkloadUID: "uid", Timestamp: in.EvaluationTime, HTTP: true, Issue: "UnresolvedContainerPort"}}}
	result := classified(t, in)
	if slices.Contains(result.Features, FeatureHTTPTraffic) || len(finding(result, FeatureHTTPTraffic).Endpoints) != 1 {
		t.Fatal("unresolved endpoint was lost or assigned")
	}
}

func TestEndpointClassificationNeedsNoUsageHistory(t *testing.T) {
	in := fixture(3600, 20)
	c := &in.Containers[0]
	c.CPU.Series = nil
	c.Memory.Series = nil
	c.Identity.ReleaseStartedAt = 0
	c.Classification = &ClassificationObservation{Endpoints: []EndpointObservation{{Namespace: "shop", Name: "Service/api", WorkloadUID: "uid", Container: "app", Timestamp: in.EvaluationTime, HTTP: true, MetricsVerified: true}}}
	result := classified(t, in)
	if !slices.Contains(result.Features, FeatureHTTPTraffic) || !slices.Contains(result.Features, FeatureMetrics) {
		t.Fatal("endpoint classification depended on utilization history")
	}
}
