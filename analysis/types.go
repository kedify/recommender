// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

// Package analysis calculates resource recommendations from raw observations without I/O.
package analysis

const (
	InputSchemaVersion               = "resource-analysis-input/v2"
	OutputSchemaVersion              = "resource-analysis-output/v2"
	ResourceRightSizeDetectorVersion = "2"
)

// All timestamps are original Unix milliseconds, never evaluation-step timestamps.
type Input struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	EvaluationTime int64                  `json:"evaluationTime"`
	WindowStart    int64                  `json:"windowStart"`
	Containers     []ContainerObservation `json:"containers"`
}
type Target struct {
	Namespace   string `json:"namespace"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Container   string `json:"container"`
	WorkloadUID string `json:"workloadUID"`
	Release     string `json:"release"`
}
type ContainerObservation struct {
	Target    Target              `json:"target"`
	Identity  CurrentIdentity     `json:"identity"`
	Inventory Inventory           `json:"inventory"`
	CPU       ResourceObservation `json:"cpu"`
	Memory    ResourceObservation `json:"memory"`
}

// ReleaseStartedAt is an activation boundary or a conservative observed segment
// start, including rollbacks. Zero asks the engine to infer the observed segment.
// Ambiguous is required when current sources disagree or mixed replicas cannot be isolated.
type CurrentIdentity struct {
	Available            bool   `json:"available"`
	WorkloadUID          string `json:"workloadUID"`
	Release              string `json:"release"`
	Timestamp            int64  `json:"timestamp"`
	ReleaseStartedAt     int64  `json:"releaseStartedAt"`
	Ambiguous            bool   `json:"ambiguous"`
	ReleaseStartInferred bool   `json:"releaseStartInferred"`
}

// Counts refer to the selected UID/release/container. Observed is a distinct
// eligible-container count, not a count of samples. Unavailable is never zero risk.
type Inventory struct {
	Available bool  `json:"available"`
	Timestamp int64 `json:"timestamp"`
	Eligible  int   `json:"eligible"`
	Observed  int   `json:"observed"`
	Excluded  int   `json:"excluded"`
}
type ResourceObservation struct {
	Series         []Series `json:"series"`
	CurrentRequest Signal   `json:"currentRequest"`
	CurrentLimit   Signal   `json:"currentLimit"`
}
type SampleKind string

const (
	SampleGauge             SampleKind = "gauge"
	SampleCPUCounterSeconds SampleKind = "cpu-counter-seconds"
)

// ID uniquely identifies an uninterrupted time series. PodUID is preferred when
// available; ID is the fallback. Never merge replicas or counter lifetimes.
type Series struct {
	ID          string     `json:"id"`
	PodUID      string     `json:"podUID,omitempty"`
	WorkloadUID string     `json:"workloadUID"`
	Release     string     `json:"release"`
	Kind        SampleKind `json:"kind"`
	Samples     []Sample   `json:"samples"`
}
type Sample struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// Signal distinguishes observed zero from missing. The timestamp is the source
// observation time; adapters mark inconsistent replica settings unavailable.
type Signal struct {
	Available bool    `json:"available"`
	Value     float64 `json:"value"`
	Timestamp int64   `json:"timestamp"`
}
type CPUStrategy string

const (
	CPUStrategyMax        CPUStrategy = "max"
	CPUStrategyPercentile CPUStrategy = "percentile"
)

type MemoryStrategy string

const MemoryStrategyMax MemoryStrategy = "max"

type Policy struct {
	CPU      CPUPolicy      `json:"cpu"`
	Memory   MemoryPolicy   `json:"memory"`
	Evidence EvidencePolicy `json:"evidence"`
}
type EvidencePolicy struct {
	MinimumHistorySeconds int64   `json:"minimumHistorySeconds"`
	MinimumSamples        int     `json:"minimumSamples"`
	MinimumCoverage       float64 `json:"minimumCoverage"`
	MaximumGapSeconds     int64   `json:"maximumGapSeconds"`
	FreshnessSeconds      int64   `json:"freshnessSeconds"`
}
type Bounds struct {
	Minimum               float64 `json:"minimum"`
	Maximum               float64 `json:"maximum"`
	MinimumAbsoluteChange float64 `json:"minimumAbsoluteChange"`
	MinimumRelativeChange float64 `json:"minimumRelativeChange"`
}
type CPUPolicy struct {
	Strategy              CPUStrategy `json:"strategy"`
	Percentile            float64     `json:"percentile,omitempty"`
	HeadroomCoefficient   float64     `json:"headroomCoefficient"`
	LimitsToRequestsRatio float64     `json:"limitsToRequestsRatio"`
	Bounds                Bounds      `json:"bounds"`
	RequestsOnly          bool        `json:"requestsOnly"`
}
type MemoryPolicy struct {
	Strategy              MemoryStrategy `json:"strategy"`
	HeadroomCoefficient   float64        `json:"headroomCoefficient"`
	LimitsToRequestsRatio float64        `json:"limitsToRequestsRatio"`
	Bounds                Bounds         `json:"bounds"`
	RequestsOnly          bool           `json:"requestsOnly"`
}
type Output struct {
	SchemaVersion   string             `json:"schemaVersion"`
	DetectorVersion string             `json:"detectorVersion"`
	PolicyVersion   string             `json:"policyVersion"`
	EffectivePolicy Policy             `json:"effectivePolicy"`
	Results         []ResourceAnalysis `json:"results"`
}
type Resource string

const (
	ResourceCPU    Resource = "cpu"
	ResourceMemory Resource = "memory"
)

type ResourceAnalysis struct {
	Target          Target           `json:"target"`
	Resource        Resource         `json:"resource"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	Evidence        ResourceEvidence `json:"evidence"`
	DataQuality     DataQuality      `json:"dataQuality"`
	NoActionReason  Reason           `json:"noActionReason,omitempty"`
}
type ResourceEvidence struct {
	AggregatedUsage Signal          `json:"aggregatedUsage"`
	CurrentRequest  Signal          `json:"currentRequest"`
	CurrentLimit    Signal          `json:"currentLimit"`
	Identity        CurrentIdentity `json:"identity"`
	Inventory       Inventory       `json:"inventory"`
}
type Setting string

const (
	SettingRequests Setting = "requests"
	SettingLimits   Setting = "limits"
)

type Recommendation struct {
	Setting        Setting `json:"setting"`
	CurrentValue   float64 `json:"currentValue"`
	SuggestedValue float64 `json:"suggestedValue"`
	Confidence     int     `json:"confidence"`
}
type DataQualityStatus string

const (
	DataQualityAvailable   DataQualityStatus = "available"
	DataQualityPartial     DataQualityStatus = "partial"
	DataQualityUnavailable DataQualityStatus = "unavailable"
)

type Reason string

const (
	ReasonInferredReleaseStart  Reason = "inferred-release-start"
	ReasonMissingIdentity       Reason = "missing-identity"
	ReasonAmbiguousIdentity     Reason = "ambiguous-identity"
	ReasonStaleIdentity         Reason = "stale-identity"
	ReasonUnknownReleaseStart   Reason = "unknown-release-start"
	ReasonMissingUsage          Reason = "missing-usage"
	ReasonUnknownSeriesIdentity Reason = "unknown-series-identity"
	ReasonInsufficientHistory   Reason = "insufficient-history"
	ReasonInsufficientSamples   Reason = "insufficient-samples"
	ReasonSparseCoverage        Reason = "sparse-coverage"
	ReasonInterruptedHistory    Reason = "interrupted-history"
	ReasonStaleUsage            Reason = "stale-usage"
	ReasonMissingRequest        Reason = "missing-current-request"
	ReasonStaleRequest          Reason = "stale-current-request"
	ReasonMissingLimit          Reason = "missing-current-limit"
	ReasonStaleLimit            Reason = "stale-current-limit"
	ReasonUnknownInventory      Reason = "unknown-inventory"
	ReasonStaleInventory        Reason = "stale-inventory"
	ReasonIncompleteInventory   Reason = "incomplete-inventory"
	ReasonExcludedContainers    Reason = "excluded-containers"
	ReasonNoMaterialChange      Reason = "no-material-change"
	ReasonBounds                Reason = "bound-applied"
	ReasonLimitDisabled         Reason = "limit-changes-disabled"
)

type DataQuality struct {
	Status                DataQualityStatus `json:"status"`
	ObservedStart         int64             `json:"observedStart"`
	ObservedEnd           int64             `json:"observedEnd"`
	SampleCount           int               `json:"sampleCount"`
	SeriesCount           int               `json:"seriesCount"`
	CadenceSeconds        float64           `json:"cadenceSeconds"`
	GapCount              int               `json:"gapCount"`
	MaximumGapSeconds     float64           `json:"maximumGapSeconds"`
	Coverage              float64           `json:"coverage"`
	ObservedIntervalHours float64           `json:"observedIntervalHours"`
	Reasons               []Reason          `json:"reasons"`
}
