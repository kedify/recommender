// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"fmt"
	"math"
	"slices"
	"sort"
)

func classifyWorkload(in Input, c ContainerObservation, p Policy) (WorkloadClassification, error) {
	obs := ClassificationObservation{}
	if c.Classification != nil {
		obs = *c.Classification
	}
	c.OOMKills = append(append([]OOMKill(nil), c.OOMKills...), obs.OOMKills...)
	c.PreviousReleases = nil
	// Throttling can establish the classification window, but is never usage
	// evidence for variance, memory leaks, or resource sizing.
	releaseEvidence := c
	releaseEvidence.CPU.Series = slices.Concat(c.CPU.Series, obs.Throttling.Seconds, obs.Throttling.ThrottledPeriods, obs.Throttling.Periods)
	c.Identity = selectReleaseSegment(in, releaseEvidence).Identity
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	out := WorkloadClassification{DetectorVersion: ClassificationDetectorVersion, Target: c.Target, WindowStart: start, WindowEnd: in.EvaluationTime, Features: []WorkloadFeature{}, Issues: append([]string(nil), obs.Issues...)}
	features := []WorkloadFeature{FeatureLeaderElection, FeatureHighVarianceCPU, FeatureHighVarianceMemory, FeatureOOMKilled, FeatureMemoryLeak, FeatureCPUThrottled, FeatureHTTPTraffic, FeatureMetrics}
	validIdentity := c.Identity.Available && !c.Identity.Ambiguous && c.Identity.WorkloadUID != "" && c.Identity.WorkloadUID == c.Target.WorkloadUID && c.Identity.Release != "" && c.Identity.Release == c.Target.Release && !stale(c.Identity.Timestamp, in, p.Evidence) && c.Identity.ReleaseStartedAt >= 0 && c.Identity.ReleaseStartedAt <= c.Identity.Timestamp
	for _, feature := range features {
		f := FeatureFinding{Feature: feature, Status: ClassificationInsufficient}
		metadataFeature := feature == FeatureLeaderElection || feature == FeatureHTTPTraffic || feature == FeatureMetrics
		if !validIdentity || (!metadataFeature && c.Identity.ReleaseStartedAt == 0) {
			f.Reasons = []string{"missing-or-ambiguous-current-identity"}
			out.Findings = append(out.Findings, f)
			continue
		}
		switch feature {
		case FeatureLeaderElection:
			f.Status = ClassificationNotDetected
			if !obs.LeasesAvailable || slices.Contains(obs.Issues, "LeaseDiscoveryUnavailable") {
				f.Status = ClassificationUnavailable
			}
			for _, lease := range obs.Leases {
				observedAt := lease.ObservedAt
				if observedAt == 0 {
					observedAt = in.EvaluationTime
				}
				if lease.Namespace == c.Target.Namespace && lease.WorkloadUID == c.Target.WorkloadUID && lease.Name != "" && lease.Timestamp > 0 && lease.Timestamp <= observedAt && !stale(observedAt, in, p.Evidence) && lease.ExpiresAt > observedAt {
					f.Leases = append(f.Leases, lease)
					f.Status = ClassificationDetected
				}
			}
			sort.Slice(f.Leases, func(i, j int) bool { return f.Leases[i].Name < f.Leases[j].Name })
		case FeatureHighVarianceCPU, FeatureHighVarianceMemory:
			series, floor := c.CPU.Series, 50.0
			if feature == FeatureHighVarianceMemory {
				series, floor = c.Memory.Series, 32*1024*1024
			}
			var err error
			f, err = classifyVariance(in, c, series, floor, feature)
			if err != nil {
				return out, err
			}
		case FeatureOOMKilled:
			kills, err := selectOOMKills(in, c)
			if err != nil {
				return out, err
			}
			f.OOMKills = kills
			// No supplied events is absence of evidence, not proof of no OOMs.
			if len(kills) > 0 {
				f.Status = ClassificationDetected
			} else {
				f.Reasons = []string{"no-supplied-oom-events"}
			}
		case FeatureMemoryLeak:
			lp := p
			if lp.Memory.LeakDetection == nil {
				normalized, err := normalizeMemoryLeakPolicy(MemoryLeakPolicy{})
				if err != nil {
					return out, err
				}
				lp.Memory.LeakDetection = &normalized
			}
			// Only obtain current data-quality and event selection; never use fallback
			// sizing evidence or leak findings to alter the original resource result.
			noOOM := c
			noOOM.OOMKills = nil
			resource, err := analyzeResource(in, noOOM, ResourceMemory, lp)
			if err != nil {
				return out, err
			}
			resource.Evidence.OOMKills, err = selectOOMKills(in, c)
			if err != nil {
				return out, err
			}
			f.MemoryLeak = analyzeMemoryLeak(in, c, lp, resource)
			switch f.MemoryLeak.Status {
			case MemoryLeakPotential:
				f.Status = ClassificationDetected
			case MemoryLeakNoPattern:
				f.Status = ClassificationNotDetected
			case MemoryLeakInsufficientData:
				f.Status = ClassificationInsufficient
			}
		case FeatureCPUThrottled:
			var err error
			f, err = classifyThrottling(in, c, obs.Throttling)
			if err != nil {
				return out, err
			}
		case FeatureHTTPTraffic, FeatureMetrics:
			f.Status = ClassificationUnavailable
			for _, ep := range obs.Endpoints {
				if ep.Namespace != c.Target.Namespace || ep.WorkloadUID != c.Target.WorkloadUID || (ep.Container != "" && ep.Container != c.Target.Container) || stale(ep.Timestamp, in, p.Evidence) {
					continue
				}
				f.Endpoints = append(f.Endpoints, ep)
				if ep.Container == c.Target.Container && (feature == FeatureHTTPTraffic && ep.HTTP || feature == FeatureMetrics && ep.MetricsVerified) {
					f.Status = ClassificationDetected
				}
			}
			sort.Slice(f.Endpoints, func(i, j int) bool {
				a, b := f.Endpoints[i], f.Endpoints[j]
				if a.Name != b.Name {
					return a.Name < b.Name
				}
				if a.Port != b.Port {
					return a.Port < b.Port
				}
				return a.Path < b.Path
			})
		}
		if f.Status == ClassificationDetected {
			out.Features = append(out.Features, feature)
		}
		out.Findings = append(out.Findings, f)
	}
	sort.Strings(out.Issues)
	return out, nil
}

func classifyVariance(in Input, c ContainerObservation, series []Series, floor float64, feature WorkloadFeature) (FeatureFinding, error) {
	f := FeatureFinding{Feature: feature, Status: ClassificationInsufficient}
	rows := append([]Series(nil), series...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, s := range rows {
		if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
			continue
		}
		windowStart := max(in.WindowStart, c.Identity.ReleaseStartedAt)
		raw, err := NormalizeSamples(s, windowStart, in.EvaluationTime)
		if err != nil {
			return f, err
		}
		if len(raw) < 2 {
			continue
		}
		// Counter conversion omits the initial source sample. Warmup starts
		// with that observation, just as it does for equivalent gauge data.
		firstSample := raw[0].Timestamp
		for _, sample := range s.Samples {
			if sample.Timestamp >= windowStart && sample.Timestamp < firstSample {
				firstSample = sample.Timestamp
			}
		}
		start := max(firstSample+5*60*1000, in.EvaluationTime-24*3600*1000)
		values := make([]Sample, 0, len(raw))
		for _, v := range raw {
			if v.Timestamp >= start {
				values = append(values, v)
			}
		}
		if len(values) < 30 || values[len(values)-1].Timestamp-values[0].Timestamp < 30*60*1000 {
			continue
		}
		gaps := sampleGaps(values)
		cadence := medianFloat(gaps)
		span := float64(values[len(values)-1].Timestamp-values[0].Timestamp) / 1000
		covered := 0.0
		mean := 0.0
		m2 := 0.0
		for i := 1; i < len(values); i++ {
			dt := gaps[i-1]
			if dt > 3*cadence {
				continue
			}
			weight := dt
			next := covered + weight
			delta := values[i].Value - mean
			mean += delta * weight / next
			m2 += weight * delta * (values[i].Value - mean)
			covered = next
		}
		coverage := covered / span
		if coverage < .7 {
			continue
		}
		e := VarianceEvidence{SeriesID: s.ID, PodUID: s.PodUID, ObservedStart: values[0].Timestamp, ObservedEnd: values[len(values)-1].Timestamp, SampleCount: len(values), Coverage: coverage}
		e.Mean = mean
		e.Variance = math.Max(0, m2/covered)
		e.StandardDeviation = math.Sqrt(e.Variance)
		if mean > 0 {
			e.CoefficientOfVariation = e.StandardDeviation / mean
		}
		sorted := make([]float64, len(values))
		for i, v := range values {
			sorted[i] = v.Value
		}
		sort.Float64s(sorted)
		e.Spread = sorted[int(math.Ceil(.95*float64(len(sorted))))-1] - sorted[int(math.Ceil(.05*float64(len(sorted))))-1]
		if !finite(e.Mean) || !finite(e.Variance) || !finite(e.StandardDeviation) || !finite(e.CoefficientOfVariation) || !finite(e.Spread) {
			return f, fmt.Errorf("variance outside numeric range")
		}
		f.Variance = append(f.Variance, e)
		if f.Status != ClassificationDetected {
			f.Status = ClassificationNotDetected
		}
		if e.CoefficientOfVariation >= .5 && e.Spread >= floor {
			f.Status = ClassificationDetected
		}
	}
	if len(f.Variance) == 0 {
		f.Reasons = []string{"requires-30-minutes-30-samples-and-70-percent-coverage-after-warmup"}
	}
	return f, nil
}
func sampleGaps(values []Sample) []float64 {
	gaps := make([]float64, 0, max(0, len(values)-1))
	for i := 1; i < len(values); i++ {
		gaps = append(gaps, float64(values[i].Timestamp-values[i-1].Timestamp)/1000)
	}
	return gaps
}
func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	return v[(len(v)-1)/2]
}

// CounterInterval is a reset-safe increment over a verified observed interval.
// No increment is inferred across a reset or a gap exceeding three cadences.
type CounterInterval struct {
	Start, End int64
	Delta      float64
}

func CounterIntervals(s Series, start, end int64) ([]CounterInterval, error) {
	if s.Kind != SampleGauge {
		return nil, fmt.Errorf("throttling counters must use raw gauge samples")
	}
	values, err := NormalizeSamples(s, start, end)
	if err != nil {
		return nil, err
	}
	cadence := medianFloat(sampleGaps(values))
	out := make([]CounterInterval, 0, max(0, len(values)-1))
	for i := 1; i < len(values); i++ {
		a, b := values[i-1], values[i]
		delta := b.Value - a.Value
		if delta < 0 || float64(b.Timestamp-a.Timestamp)/1000 > 3*cadence {
			continue
		}
		out = append(out, CounterInterval{Start: a.Timestamp, End: b.Timestamp, Delta: delta})
	}
	return out, nil
}
func classifyThrottling(in Input, c ContainerObservation, obs CPUThrottlingObservation) (FeatureFinding, error) {
	f := FeatureFinding{Feature: FeatureCPUThrottled, Status: ClassificationInsufficient}
	groups := []map[string]Series{{}, {}, {}}
	for i, rows := range [][]Series{obs.Seconds, obs.ThrottledPeriods, obs.Periods} {
		for _, s := range rows {
			if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
				continue
			}
			if s.ID == "" {
				return f, fmt.Errorf("throttling series ID required")
			}
			if _, ok := groups[i][s.ID]; ok {
				return f, fmt.Errorf("duplicate throttling series %q", s.ID)
			}
			groups[i][s.ID] = s
		}
	}
	keys := map[string]bool{}
	for _, g := range groups {
		for id := range g {
			keys[id] = true
		}
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := CPUThrottlingEvidence{SeriesID: id}
		intervals := make([][]CounterInterval, 3)
		for i, g := range groups {
			if s, ok := g[id]; ok {
				if s.PodUID != "" {
					if e.PodUID != "" && s.PodUID != e.PodUID {
						return f, fmt.Errorf("throttling counter identities disagree")
					}
					e.PodUID = s.PodUID
				}
				var err error
				intervals[i], err = CounterIntervals(s, max(in.WindowStart, c.Identity.ReleaseStartedAt), in.EvaluationTime)
				if err != nil {
					return f, err
				}
			}
		}
		if len(intervals[0]) > 0 {
			seconds := 0.0
			for _, v := range intervals[0] {
				seconds += v.Delta
				e.ObservedSeconds += float64(v.End-v.Start) / 1000
			}
			rate := seconds / e.ObservedSeconds
			e.ThrottledSeconds = &seconds
			e.SecondsPerSecond = &rate
		}
		if len(intervals[1]) > 0 {
			count := 0.0
			for _, v := range intervals[1] {
				count += v.Delta
			}
			e.ThrottledPeriods = &count
		}
		// Percentages use only exactly matching intervals from both counters.
		periods, throttled := 0.0, 0.0
		denom := map[[2]int64]float64{}
		for _, v := range intervals[2] {
			denom[[2]int64{v.Start, v.End}] = v.Delta
		}
		for _, v := range intervals[1] {
			if d, ok := denom[[2]int64{v.Start, v.End}]; ok && d > 0 && v.Delta <= d {
				periods += d
				throttled += v.Delta
			}
		}
		if periods > 0 {
			percent := 100 * throttled / periods
			e.Periods = &periods
			e.ThrottledPeriodPercent = &percent
		}
		if e.ThrottledSeconds == nil && e.ThrottledPeriods == nil {
			continue
		}
		if e.SecondsPerSecond != nil && !finite(*e.SecondsPerSecond) || e.ThrottledPeriods != nil && !finite(*e.ThrottledPeriods) {
			return f, fmt.Errorf("throttling outside numeric range")
		}
		for _, value := range []*float64{e.ThrottledSeconds, e.SecondsPerSecond, e.Periods, e.ThrottledPeriods, e.ThrottledPeriodPercent} {
			if value != nil && !finite(*value) {
				return f, fmt.Errorf("throttling outside numeric range")
			}
		}
		f.Throttling = append(f.Throttling, e)
		if f.Status != ClassificationDetected {
			f.Status = ClassificationNotDetected
		}
		if e.ThrottledSeconds != nil && *e.ThrottledSeconds > 0 || e.ThrottledPeriods != nil && *e.ThrottledPeriods > 0 {
			f.Status = ClassificationDetected
		}
	}
	return f, nil
}
