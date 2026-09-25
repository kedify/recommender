// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"fmt"
	"math"
	"sort"
)

const maxMemoryLeakBuckets = 256

func normalizeMemoryLeakPolicy(p MemoryLeakPolicy) (MemoryLeakPolicy, error) {
	for _, field := range []struct {
		value    *int64
		fallback int64
	}{
		{&p.LookbackSeconds, 24 * 3600},
		{&p.BucketDurationSeconds, 30 * 60},
		{&p.MinimumHistorySeconds, 6 * 3600},
		{&p.WarmupSeconds, 30 * 60},
	} {
		if *field.value == 0 {
			*field.value = field.fallback
		}
		if *field.value < 1 || *field.value > math.MaxInt64/1000 {
			return MemoryLeakPolicy{}, fmt.Errorf("memory.leakDetection durations must be positive and fit Unix milliseconds")
		}
	}
	if p.MinimumSamplesPerBucket == 0 {
		p.MinimumSamplesPerBucket = 5
	}
	if p.MinimumGrowthBytes == 0 {
		p.MinimumGrowthBytes = 64 * 1024 * 1024
	}
	if p.MinimumRelativeGrowth == 0 {
		p.MinimumRelativeGrowth = .2
	}
	if p.MinimumTrendConsistency == 0 {
		p.MinimumTrendConsistency = .8
	}
	if p.MinimumSamplesPerBucket < 2 || !positive(p.MinimumGrowthBytes) || !positive(p.MinimumRelativeGrowth) || !finite(p.MinimumTrendConsistency) || p.MinimumTrendConsistency <= .5 || p.MinimumTrendConsistency > 1 {
		return MemoryLeakPolicy{}, fmt.Errorf("invalid memory.leakDetection samples, growth thresholds or trend consistency (must be in (0.5,1])")
	}
	if p.MinimumHistorySeconds > p.LookbackSeconds || p.WarmupSeconds >= p.LookbackSeconds || p.MinimumHistorySeconds/p.BucketDurationSeconds < 12 {
		return MemoryLeakPolicy{}, fmt.Errorf("memory.leakDetection requires at least 12 buckets of history within the lookback and a shorter warmup")
	}
	// Bound quadratic pairwise regression independently of raw sample count.
	if p.LookbackSeconds/p.BucketDurationSeconds > maxMemoryLeakBuckets || p.LookbackSeconds/p.BucketDurationSeconds == maxMemoryLeakBuckets && p.LookbackSeconds%p.BucketDurationSeconds != 0 {
		return MemoryLeakPolicy{}, fmt.Errorf("memory.leakDetection lookback must span at most %d buckets", maxMemoryLeakBuckets)
	}
	return p, nil
}

func analyzeMemoryLeak(in Input, c ContainerObservation, p Policy, resource ResourceAnalysis) *MemoryLeakAnalysis {
	lp := *p.Memory.LeakDetection
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt, in.EvaluationTime-lp.LookbackSeconds*1000)
	out := &MemoryLeakAnalysis{
		DetectorVersion: MemoryLeakDetectorVersion, Status: MemoryLeakInsufficientData,
		WindowStart: start, WindowEnd: in.EvaluationTime, Reasons: []Reason{}, Episodes: []MemoryLeakEvidence{},
	}
	for _, reason := range resource.DataQuality.Reasons {
		switch reason {
		case ReasonMissingIdentity, ReasonAmbiguousIdentity, ReasonStaleIdentity, ReasonUnknownReleaseStart, ReasonUnknownSeriesIdentity:
			out.Reasons = append(out.Reasons, reason)
		}
	}
	if len(out.Reasons) > 0 {
		return out
	}
	series := append([]Series(nil), c.Memory.Series...)
	sort.Slice(series, func(i, j int) bool { return series[i].ID < series[j].ID })
	for _, s := range series {
		if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
			continue
		}
		// analyzeResource already validated selected series and conflicting samples.
		// Keep the first observed time before the leak lookback for warmup handling.
		firstObserved := int64(0)
		var samples []Sample
		for _, sample := range s.Samples {
			if sample.Timestamp < max(in.WindowStart, c.Identity.ReleaseStartedAt) || sample.Timestamp > in.EvaluationTime {
				continue
			}
			if firstObserved == 0 || sample.Timestamp < firstObserved {
				firstObserved = sample.Timestamp
			}
			if sample.Timestamp >= start {
				samples = append(samples, sample)
			}
		}
		if len(samples) == 0 {
			// Keep missing series in the coverage accounting: another replica's
			// stable baseline cannot establish that this lifetime has no leak.
			reason := ReasonMissingUsage
			if firstObserved > 0 {
				reason = ReasonStaleUsage
			}
			out.Episodes = append(out.Episodes, MemoryLeakEvidence{
				SeriesID: s.ID, PodUID: s.PodUID, Status: MemoryLeakInsufficientData,
				Reasons: []Reason{reason},
			})
			out.SkippedEpisodes++
			continue
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i].Timestamp < samples[j].Timestamp })
		clean := samples[:0]
		for _, sample := range samples {
			if len(clean) == 0 || clean[len(clean)-1].Timestamp != sample.Timestamp {
				clean = append(clean, sample)
			}
		}
		for _, episode := range memoryLeakEpisodes(clean, s.PodUID, firstObserved, resource.Evidence.OOMKills, p.Evidence.FreshnessSeconds) {
			evidence := analyzeMemoryEpisode(in, s, episode, start, p)
			out.Episodes = append(out.Episodes, evidence)
			switch evidence.Status {
			case MemoryLeakPotential:
				out.SuspectedEpisodes++
				out.EvaluatedEpisodes++
			case MemoryLeakNoPattern:
				out.EvaluatedEpisodes++
			case MemoryLeakInsufficientData:
				out.SkippedEpisodes++
			}
		}
	}
	switch {
	case out.SuspectedEpisodes > 0:
		out.Status = MemoryLeakPotential
		out.Reasons = append(out.Reasons, ReasonMemoryBaselineGrowth)
	case out.EvaluatedEpisodes > 0 && out.SkippedEpisodes == 0:
		out.Status = MemoryLeakNoPattern
		out.Reasons = append(out.Reasons, ReasonMemoryBaselineStable)
	case len(out.Episodes) == 0:
		out.Reasons = append(out.Reasons, ReasonMissingUsage)
	default:
		// Details (history, freshness, coverage) stay with their episode.
		for _, e := range out.Episodes {
			if e.Status == MemoryLeakInsufficientData {
				for _, reason := range e.Reasons {
					out.Reasons = appendUniqueReason(out.Reasons, reason)
				}
			}
		}
	}
	return out
}

type memoryEpisode struct {
	samples       []Sample
	firstObserved int64
	oomIDs        []string
}

func memoryLeakEpisodes(samples []Sample, podUID string, firstObserved int64, kills []OOMKill, freshnessSeconds int64) []memoryEpisode {
	var episodes []memoryEpisode
	position := 0
	for _, kill := range kills {
		if podUID == "" || kill.PodUID != podUID || position == len(samples) || kill.Timestamp < samples[position].Timestamp {
			continue
		}
		end := position
		for end < len(samples) && samples[end].Timestamp <= kill.Timestamp {
			end++
		}
		if end == position {
			continue
		}
		episode := memoryEpisode{samples: samples[position:end], firstObserved: firstObserved}
		// A distant event must not make an otherwise stale series look complete.
		if float64(kill.Timestamp-samples[end-1].Timestamp)/1000 <= float64(freshnessSeconds) {
			episode.oomIDs = []string{kill.ID}
		}
		episodes = append(episodes, episode)
		position = end
		if position < len(samples) {
			firstObserved = samples[position].Timestamp
		}
	}
	if position < len(samples) {
		episodes = append(episodes, memoryEpisode{samples: samples[position:], firstObserved: firstObserved})
	}
	return episodes
}

func analyzeMemoryEpisode(in Input, s Series, episode memoryEpisode, windowStart int64, p Policy) MemoryLeakEvidence {
	lp := *p.Memory.LeakDetection
	e := MemoryLeakEvidence{SeriesID: s.ID, PodUID: s.PodUID, Status: MemoryLeakInsufficientData, OOMKillIDs: episode.oomIDs, Reasons: []Reason{}}
	if lp.WarmupSeconds*1000 > in.EvaluationTime-episode.firstObserved {
		e.Reasons = append(e.Reasons, ReasonInsufficientHistory)
		return e
	}
	start := max(windowStart, episode.firstObserved+lp.WarmupSeconds*1000)
	first := sort.Search(len(episode.samples), func(i int) bool { return episode.samples[i].Timestamp >= start })
	samples := episode.samples[first:]
	e.SampleCount = len(samples)
	if len(samples) < 2 {
		e.Reasons = append(e.Reasons, ReasonInsufficientSamples)
		return e
	}
	e.ObservedStart, e.ObservedEnd = samples[0].Timestamp, samples[len(samples)-1].Timestamp
	if stale(e.ObservedEnd, in, p.Evidence) && len(episode.oomIDs) == 0 {
		e.Reasons = append(e.Reasons, ReasonStaleUsage)
	}
	gaps := make([]float64, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		gap := float64(samples[i].Timestamp - samples[i-1].Timestamp)
		gaps = append(gaps, gap)
	}
	cadence := medianMemoryValues(gaps)
	// At most one observed cadence of edge tolerance; never extrapolate to now.
	end := e.ObservedEnd + int64(math.Min(cadence, float64(in.EvaluationTime-e.ObservedEnd)))
	bucketMillis := lp.BucketDurationSeconds * 1000
	e.BucketCount = int((end - start) / bucketMillis)
	if e.BucketCount < 12 || int64(e.BucketCount)*lp.BucketDurationSeconds < lp.MinimumHistorySeconds {
		e.Reasons = append(e.Reasons, ReasonMemoryLeakBuckets)
		return e
	}
	buckets := make([][]Sample, e.BucketCount)
	for _, sample := range samples {
		index := int((sample.Timestamp - start) / bucketMillis)
		if index < len(buckets) {
			buckets[index] = append(buckets[index], sample)
		}
	}
	baselines := make([]float64, 0, len(buckets))
	baselineHours := make([]float64, 0, len(buckets))
	for i, bucket := range buckets {
		if len(bucket) == 0 {
			continue
		}
		covered := math.Min(cadence, float64(bucketMillis))
		values := make([]float64, len(bucket))
		for j, sample := range bucket {
			values[j] = sample.Value
			if j > 0 {
				covered += math.Min(cadence, float64(sample.Timestamp-bucket[j-1].Timestamp))
			}
		}
		coverage := math.Min(1, covered/float64(bucketMillis))
		e.Coverage += coverage / float64(len(buckets))
		if len(bucket) < lp.MinimumSamplesPerBucket {
			continue
		}
		sort.Float64s(values)
		baselines = append(baselines, values[(len(values)+9)/10-1]) // Nearest-rank P10.
		baselineHours = append(baselineHours, float64(i)*float64(lp.BucketDurationSeconds)/3600)
	}
	e.Coverage = math.Min(1, e.Coverage)
	if e.Coverage < p.Evidence.MinimumCoverage {
		e.Reasons = appendUniqueReason(e.Reasons, ReasonSparseCoverage)
	}
	if len(baselines) < 12 || int64(len(baselines))*lp.BucketDurationSeconds < lp.MinimumHistorySeconds {
		e.Reasons = appendUniqueReason(e.Reasons, ReasonMemoryLeakBuckets)
	}
	if len(e.Reasons) > 0 {
		return e
	}
	quarter := len(baselines) / 4
	e.BaselineStartBytes = medianMemoryValues(append([]float64(nil), baselines[:quarter]...))
	e.BaselineEndBytes = medianMemoryValues(append([]float64(nil), baselines[len(baselines)-quarter:]...))
	e.GrowthBytes = e.BaselineEndBytes - e.BaselineStartBytes
	if e.BaselineStartBytes > 0 {
		relative := e.GrowthBytes / e.BaselineStartBytes
		if !finite(relative) {
			e.Reasons = append(e.Reasons, ReasonMemoryLeakNumericRange)
			return e
		}
		e.RelativeGrowth = &relative
	}
	e.SlopeBytesPerHour, e.TrendConsistency = memoryBaselineTrend(baselines, baselineHours)
	// Require growth to continue near the end, not just earlier in the lookback.
	// Six buckets keep this check meaningful even with the minimum history.
	recentBuckets := max(6, len(baselines)/4)
	e.RecentSlopeBytesPerHour, e.RecentTrendConsistency = memoryBaselineTrend(baselines[len(baselines)-recentBuckets:], baselineHours[len(baselines)-recentBuckets:])
	if !finite(e.SlopeBytesPerHour) || !finite(e.RecentSlopeBytesPerHour) {
		e.SlopeBytesPerHour, e.RecentSlopeBytesPerHour = 0, 0
		e.Reasons = append(e.Reasons, ReasonMemoryLeakNumericRange)
		return e
	}
	e.Status = MemoryLeakNoPattern
	if e.GrowthBytes < lp.MinimumGrowthBytes || e.RelativeGrowth != nil && *e.RelativeGrowth < lp.MinimumRelativeGrowth || e.SlopeBytesPerHour <= 0 || e.TrendConsistency < lp.MinimumTrendConsistency {
		e.Reasons = append(e.Reasons, ReasonMemoryBaselineStable)
		return e
	}
	if e.RecentSlopeBytesPerHour <= 0 || e.RecentSlopeBytesPerHour < .25*e.SlopeBytesPerHour || e.RecentTrendConsistency < lp.MinimumTrendConsistency {
		e.Reasons = append(e.Reasons, ReasonMemoryBaselineRecovery)
		return e
	}
	e.Status = MemoryLeakPotential
	e.Reasons = append(e.Reasons, ReasonMemoryBaselineGrowth)
	if len(e.OOMKillIDs) > 0 {
		e.Reasons = append(e.Reasons, ReasonOOMKillDetected)
	}
	return e
}

func memoryBaselineTrend(values, hours []float64) (float64, float64) {
	slopes := make([]float64, 0, len(values)*(len(values)-1)/2)
	increasing := 0
	for i, first := range values {
		for j := i + 1; j < len(values); j++ {
			slope := (values[j] - first) / (hours[j] - hours[i])
			slopes = append(slopes, slope)
			if slope > 0 {
				increasing++
			}
		}
	}
	return medianMemoryValues(slopes), float64(increasing) / float64(len(slopes))
}

func medianMemoryValues(values []float64) float64 {
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 != 0 {
		return values[middle]
	}
	return values[middle-1]/2 + values[middle]/2
}

func appendUniqueReason(reasons []Reason, reason Reason) []Reason {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}
