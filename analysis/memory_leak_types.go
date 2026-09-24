// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

const MemoryLeakDetectorVersion = "2"

// MemoryLeakPolicy enables an advisory heuristic, not a diagnosis. Zero fields
// select defaults. Setting MemoryPolicy.LeakDetection to nil disables detection.
// Coverage and freshness come from Policy.Evidence. Leak history is
// independent of the longer history required for resource sizing.
type MemoryLeakPolicy struct {
	LookbackSeconds         int64   `json:"lookbackSeconds"`
	BucketDurationSeconds   int64   `json:"bucketDurationSeconds"`
	MinimumHistorySeconds   int64   `json:"minimumHistorySeconds"`
	WarmupSeconds           int64   `json:"warmupSeconds"`
	MinimumSamplesPerBucket int     `json:"minimumSamplesPerBucket"`
	MinimumGrowthBytes      float64 `json:"minimumGrowthBytes"`
	MinimumRelativeGrowth   float64 `json:"minimumRelativeGrowth"`
	MinimumTrendConsistency float64 `json:"minimumTrendConsistency"`
}

type MemoryLeakStatus string

const (
	MemoryLeakPotential        MemoryLeakStatus = "potential-leak"
	MemoryLeakNoPattern        MemoryLeakStatus = "no-leak-pattern"
	MemoryLeakInsufficientData MemoryLeakStatus = "insufficient-data"
)

const (
	ReasonPotentialMemoryLeak    Reason = "potential-memory-leak"
	ReasonMemoryBaselineGrowth   Reason = "sustained-memory-baseline-growth"
	ReasonMemoryBaselineStable   Reason = "no-sustained-memory-baseline-growth"
	ReasonMemoryBaselineRecovery Reason = "memory-baseline-plateau-or-recovery"
	ReasonMemoryLeakBuckets      Reason = "insufficient-memory-trend-buckets"
	ReasonMemoryLeakNumericRange Reason = "memory-trend-outside-numeric-range"
)

// MemoryLeakAnalysis summarizes only the selected release and supplied series.
// A potential leak means at least one episode passed the heuristic. NoPattern is
// reported only when every considered episode could be evaluated. Neither status
// proves whether allocations are useful: load, caches and runtime heaps are not
// part of this input. The independent detector version identifies this heuristic.
type MemoryLeakAnalysis struct {
	DetectorVersion   string               `json:"detectorVersion"`
	Status            MemoryLeakStatus     `json:"status"`
	WindowStart       int64                `json:"windowStart"`
	WindowEnd         int64                `json:"windowEnd"`
	EvaluatedEpisodes int                  `json:"evaluatedEpisodes"`
	SuspectedEpisodes int                  `json:"suspectedEpisodes"`
	SkippedEpisodes   int                  `json:"skippedEpisodes"`
	Reasons           []Reason             `json:"reasons"`
	Episodes          []MemoryLeakEvidence `json:"episodes"`
}

// MemoryLeakEvidence describes one container episode. Known OOM
// terminations split episodes even if an adapter reused a series ID. Baselines
// are medians of the first/last quarters of per-bucket P10 values. Slopes use
// Theil-Sen (median pairwise slope); consistency is the fraction of increasing
// pairs, not a probability or statistical confidence. RelativeGrowth is absent
// when the starting baseline is zero. Recent statistics use the latest quarter
// of buckets, with a minimum of six buckets. OOMKillIDs refer to evidence.oomKills
// and only corroborate an episode when its last sample is close to that termination.
type MemoryLeakEvidence struct {
	SeriesID                string           `json:"seriesID"`
	PodUID                  string           `json:"podUID,omitempty"`
	Status                  MemoryLeakStatus `json:"status"`
	ObservedStart           int64            `json:"observedStart"`
	ObservedEnd             int64            `json:"observedEnd"`
	SampleCount             int              `json:"sampleCount"`
	BucketCount             int              `json:"bucketCount"`
	Coverage                float64          `json:"coverage"`
	BaselineStartBytes      float64          `json:"baselineStartBytes"`
	BaselineEndBytes        float64          `json:"baselineEndBytes"`
	GrowthBytes             float64          `json:"growthBytes"`
	RelativeGrowth          *float64         `json:"relativeGrowth,omitempty"`
	SlopeBytesPerHour       float64          `json:"slopeBytesPerHour"`
	RecentSlopeBytesPerHour float64          `json:"recentSlopeBytesPerHour"`
	TrendConsistency        float64          `json:"trendConsistency"`
	RecentTrendConsistency  float64          `json:"recentTrendConsistency"`
	OOMKillIDs              []string         `json:"oomKillIDs,omitempty"`
	Reasons                 []Reason         `json:"reasons"`
}
