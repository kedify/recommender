// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

// Package analysis calculates resource recommendations from raw observations without I/O.
package analysis

const (
	InputSchemaVersion               = "resource-analysis-input/v2"
	OutputSchemaVersion              = "resource-analysis-output/v3"
	ResourceRightSizeDetectorVersion = "8"
	MaxPreviousReleases              = 3
)

// All timestamps are Unix milliseconds. Observation timestamps retain the source
// time; evaluationTime and windowStart define the requested analysis window.
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
	OOMKills  []OOMKill           `json:"oomKills,omitempty"`
	// Newest first. Only the first three entries are eligible as fallback usage.
	PreviousReleases []PreviousRelease `json:"previousReleases,omitempty"`
}

// PreviousRelease supplies raw usage from an earlier rollout of this workload.
// EvaluationTime is the last historical observation, not today's timestamp.
// ReleaseStartedAt may be zero to infer the observed segment. Current settings,
// inventory, OOM events and leak findings always refer to the current rollout.
type PreviousRelease struct {
	Release          string   `json:"release"`
	ReleaseStartedAt int64    `json:"releaseStartedAt,omitempty"`
	EvaluationTime   int64    `json:"evaluationTime"`
	CPU              []Series `json:"cpu"`
	Memory           []Series `json:"memory"`
}

// OOMKill is a positive out-of-memory termination observation for this container.
// ID identifies the event, independently of its source (for example, pod UID plus
// termination time). Repeated observations of the same event must retain its ID
// and original Unix-millisecond Timestamp, not a scrape or query evaluation time.
// WorkloadUID and Release describe the container at termination. PodUID is optional.
// MemoryLimitBytes is the positive memory limit in effect at termination, when
// known; zero means no known finite limit. Do not substitute a later/current limit.
// Omitted OOMKills means no supplied evidence, not proof that no OOMs occurred.
type OOMKill struct {
	ID               string  `json:"id"`
	PodUID           string  `json:"podUID,omitempty"`
	WorkloadUID      string  `json:"workloadUID"`
	Release          string  `json:"release"`
	Timestamp        int64   `json:"timestamp"`
	MemoryLimitBytes float64 `json:"memoryLimitBytes,omitempty"`
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

// ID uniquely identifies a container lifetime's time series. PodUID is preferred when
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

// Signal distinguishes observed zero, known unset allocations, and missing data.
// For current requests/limits, Available=true with Unset=true means the setting
// was observed to be absent; Value must be zero and is not a numeric allocation.
// Unset defaults to false so existing numeric signals keep their meaning.
// The timestamp is the source observation time; adapters mark inconsistent
// replica settings unavailable.
// Aggregated usage retains the selected sample's timestamp (the interval end for
// a CPU rate). DataQuality.ObservedEnd separately reports the latest usable sample.
type Signal struct {
	Available bool    `json:"available"`
	Unset     bool    `json:"unset,omitempty"`
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
	OOMKilledCoefficient  float64        `json:"oomKilledCoefficient"`
	LimitsToRequestsRatio float64        `json:"limitsToRequestsRatio"`
	Bounds                Bounds         `json:"bounds"`
	RequestsOnly          bool           `json:"requestsOnly"`
	// Nil disables leak detection; an empty policy enables its defaults.
	LeakDetection *MemoryLeakPolicy `json:"leakDetection,omitempty"`
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
	DecisionTrace   *DecisionTrace      `json:"decisionTrace,omitempty"`
	Target          Target              `json:"target"`
	Resource        Resource            `json:"resource"`
	Recommendations []Recommendation    `json:"recommendations,omitempty"`
	Evidence        ResourceEvidence    `json:"evidence"`
	DataQuality     DataQuality         `json:"dataQuality"`
	NoActionReason  Reason              `json:"noActionReason,omitempty"`
	Notices         []Reason            `json:"notices,omitempty"`
	OOMAdjustment   *OOMAdjustment      `json:"oomAdjustment,omitempty"`
	MemoryLeak      *MemoryLeakAnalysis `json:"memoryLeak,omitempty"`
	RolloutFallback *RolloutFallback    `json:"rolloutFallback,omitempty"`
}

// RolloutFallback identifies historical usage used to size the current target.
// DataQuality and AggregatedUsage describe this source; CurrentDataQuality
// preserves the reason current-rollout usage was insufficient.
type RolloutFallback struct {
	Release              string      `json:"release"`
	ReleaseStartedAt     int64       `json:"releaseStartedAt"`
	ReleaseStartInferred bool        `json:"releaseStartInferred"`
	EvaluationTime       int64       `json:"evaluationTime"`
	CurrentDataQuality   DataQuality `json:"currentDataQuality"`
}

// OOMAdjustment records memory sizing before bounds and material-change guards.
// The request candidate is max(BaselineRequestBytes, OOMRequestFloorBytes).
// Events without a known failed limit use the current finite memory limit,
// then the current request, then qualifying usage. The fallback flags identify
// which sources were used without presenting current settings as historical facts.
// Presence does not promise an emitted recommendation: the remaining guards apply.
type OOMAdjustment struct {
	BaselineRequestBytes float64 `json:"baselineRequestBytes"`
	OOMRequestFloorBytes float64 `json:"oomRequestFloorBytes"`
	UsedUsageFallback    bool    `json:"usedUsageFallback"`
	UsedCurrentFallback  bool    `json:"usedCurrentFallback,omitempty"`
}

type ResourceEvidence struct {
	AggregatedUsage Signal          `json:"aggregatedUsage"`
	CurrentRequest  Signal          `json:"currentRequest"`
	CurrentLimit    Signal          `json:"currentLimit"`
	Identity        CurrentIdentity `json:"identity"`
	Inventory       Inventory       `json:"inventory"`
	OOMKills        []OOMKill       `json:"oomKills,omitempty"`
}
type Setting string

const (
	SettingRequests Setting = "requests"
	SettingLimits   Setting = "limits"
)

type Recommendation struct {
	Setting      Setting `json:"setting"`
	CurrentValue float64 `json:"currentValue"`
	// CurrentUnset means CurrentValue is a placeholder, not an observed zero.
	CurrentUnset   bool    `json:"currentUnset,omitempty"`
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
	ReasonOOMKillDetected       Reason = "oom-kill-detected"
	ReasonOOMLimitUnknown       Reason = "unknown-oom-memory-limit"
)

type DataQuality struct {
	Status        DataQualityStatus `json:"status"`
	ObservedStart int64             `json:"observedStart"`
	ObservedEnd   int64             `json:"observedEnd"`
	SampleCount   int               `json:"sampleCount"`
	// ObservationCount counts distinct timestamps across series after normalization,
	// including CPU counter conversion. MinimumSamples applies to this count.
	ObservationCount      int      `json:"observationCount"`
	SeriesCount           int      `json:"seriesCount"`
	CadenceSeconds        float64  `json:"cadenceSeconds"`
	Coverage              float64  `json:"coverage"`
	ObservedIntervalHours float64  `json:"observedIntervalHours"`
	Reasons               []Reason `json:"reasons"`
}
