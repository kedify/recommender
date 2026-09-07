// Package analysis calculates resource recommendations from normalized observations.
package analysis

const (
	InputSchemaVersion  = "resource-analysis-input/v1"
	OutputSchemaVersion = "resource-analysis-output/v1"
	// ResourceRightSizeDetectorVersion identifies the calculation algorithm
	// independently from input/output schemas and caller policy.
	ResourceRightSizeDetectorVersion = "1"
)

type Input struct {
	SchemaVersion         string                 `json:"schemaVersion"`
	ObservedIntervalHours int                    `json:"observedIntervalHours"`
	Containers            []ContainerObservation `json:"containers"`
}

type ContainerObservation struct {
	Target Target              `json:"target"`
	CPU    ResourceObservation `json:"cpu"`
	Memory ResourceObservation `json:"memory"`
}

type Target struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
}

// ResourceObservation contains values normalized to bytes for memory and millicores
// for CPU. AggregatedUsage is selected over the observation interval according to
// the corresponding policy before the input reaches this package.
type ResourceObservation struct {
	AggregatedUsage Signal `json:"aggregatedUsage"`
	CurrentRequest  Signal `json:"currentRequest"`
	CurrentLimit    Signal `json:"currentLimit"`
}

// Signal distinguishes a measured zero from a missing value.
type Signal struct {
	Available bool    `json:"available"`
	Value     float64 `json:"value"`
}

type CPUStrategy string

const (
	CPUStrategyMax        CPUStrategy = "max"
	CPUStrategyPercentile CPUStrategy = "percentile"
)

type MemoryStrategy string

const MemoryStrategyMax MemoryStrategy = "max"

type Policy struct {
	CPU    CPUPolicy    `json:"cpu"`
	Memory MemoryPolicy `json:"memory"`
}

type CPUPolicy struct {
	Strategy              CPUStrategy `json:"strategy"`
	Percentile            float64     `json:"percentile,omitempty"`
	HeadroomCoefficient   float64     `json:"headroomCoefficient"`
	LimitsToRequestsRatio float64     `json:"limitsToRequestsRatio"`
}

type MemoryPolicy struct {
	Strategy              MemoryStrategy `json:"strategy"`
	HeadroomCoefficient   float64        `json:"headroomCoefficient"`
	LimitsToRequestsRatio float64        `json:"limitsToRequestsRatio"`
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
	Target          Target              `json:"target"`
	Resource        Resource            `json:"resource"`
	Recommendations []Recommendation    `json:"recommendations,omitempty"`
	Evidence        ResourceObservation `json:"evidence"`
	DataQuality     DataQuality         `json:"dataQuality"`
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

type DataQuality struct {
	Status                DataQualityStatus `json:"status"`
	ObservedIntervalHours int               `json:"observedIntervalHours"`
	MissingSignals        []SignalName      `json:"missingSignals,omitempty"`
}

type SignalName string

const (
	SignalAggregatedUsage SignalName = "aggregated-usage"
	SignalCurrentRequest  SignalName = "current-request"
	SignalCurrentLimit    SignalName = "current-limit"
)
