// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

const ClassificationDetectorVersion = "1"

// ClassificationPolicy enables advisory classification with versioned defaults.
// It never changes resource sizing, OOM adjustments or sizing notices.
type ClassificationPolicy struct{}

type WorkloadFeature string

const (
	FeatureLeaderElection     WorkloadFeature = "leader-election"
	FeatureHighVarianceCPU    WorkloadFeature = "high-variance-cpu"
	FeatureHighVarianceMemory WorkloadFeature = "high-variance-memory"
	FeatureOOMKilled          WorkloadFeature = "oom-killed"
	FeatureMemoryLeak         WorkloadFeature = "memory-leak"
	FeatureCPUThrottled       WorkloadFeature = "cpu-throttled"
	FeatureHTTPTraffic        WorkloadFeature = "has-http-traffic"
	FeatureMetrics            WorkloadFeature = "has-metrics"
)

type ClassificationStatus string

const (
	ClassificationDetected     ClassificationStatus = "detected"
	ClassificationNotDetected  ClassificationStatus = "not-detected"
	ClassificationInsufficient ClassificationStatus = "insufficient-data"
	ClassificationUnavailable  ClassificationStatus = "unavailable"
)

// ClassificationObservation contains optional, adapter-attributed evidence.
// OOMKills here are classification-only and cannot affect sizing. Throttling
// series hold raw cumulative counters with Kind=SampleGauge, never CPU usage.
type ClassificationObservation struct {
	LeasesAvailable bool                     `json:"leasesAvailable,omitempty"`
	Leases          []LeaseObservation       `json:"leases,omitempty"`
	Endpoints       []EndpointObservation    `json:"endpoints,omitempty"`
	OOMKills        []OOMKill                `json:"oomKills,omitempty"`
	Throttling      CPUThrottlingObservation `json:"throttling"`
	Issues          []string                 `json:"issues,omitempty"`
}

// WorkloadUID and PodUID must be established by the adapter from ownership or
// an unambiguous holder identity, never from namespace/name proximity alone.
type LeaseObservation struct {
	ObservedAt  int64  `json:"observedAt,omitempty"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	WorkloadUID string `json:"workloadUID"`
	PodUID      string `json:"podUID,omitempty"`
	Timestamp   int64  `json:"timestamp"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// Endpoint observations retain resolved container identity. HTTP is a metadata
// heuristic; MetricsVerified requires a successful response with metric samples.
// No response bodies, arbitrary headers or secret-bearing URLs belong here.
type EndpointObservation struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	WorkloadUID     string `json:"workloadUID"`
	Container       string `json:"container"`
	PodUID          string `json:"podUID,omitempty"`
	Port            int32  `json:"port"`
	Path            string `json:"path,omitempty"`
	Scheme          string `json:"scheme,omitempty"`
	HTTP            bool   `json:"http,omitempty"`
	MetricsVerified bool   `json:"metricsVerified,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Issue           string `json:"issue,omitempty"`
}
type CPUThrottlingObservation struct {
	Seconds          []Series `json:"seconds,omitempty"`
	ThrottledPeriods []Series `json:"throttledPeriods,omitempty"`
	Periods          []Series `json:"periods,omitempty"`
}
type WorkloadClassification struct {
	DetectorVersion string            `json:"detectorVersion"`
	Target          Target            `json:"target"`
	WindowStart     int64             `json:"windowStart"`
	WindowEnd       int64             `json:"windowEnd"`
	Features        []WorkloadFeature `json:"features"`
	Findings        []FeatureFinding  `json:"findings"`
	Issues          []string          `json:"issues,omitempty"`
}
type FeatureFinding struct {
	Feature    WorkloadFeature         `json:"feature"`
	Status     ClassificationStatus    `json:"status"`
	Reasons    []string                `json:"reasons,omitempty"`
	Variance   []VarianceEvidence      `json:"variance,omitempty"`
	Throttling []CPUThrottlingEvidence `json:"throttling,omitempty"`
	Leases     []LeaseObservation      `json:"leases,omitempty"`
	Endpoints  []EndpointObservation   `json:"endpoints,omitempty"`
	OOMKills   []OOMKill               `json:"oomKills,omitempty"`
	MemoryLeak *MemoryLeakAnalysis     `json:"memoryLeak,omitempty"`
}
type VarianceEvidence struct {
	SeriesID               string  `json:"seriesID"`
	PodUID                 string  `json:"podUID,omitempty"`
	ObservedStart          int64   `json:"observedStart"`
	ObservedEnd            int64   `json:"observedEnd"`
	SampleCount            int     `json:"sampleCount"`
	Coverage               float64 `json:"coverage"`
	CoefficientOfVariation float64 `json:"coefficientOfVariation"`
	Spread                 float64 `json:"spread"`
}
type CPUThrottlingEvidence struct {
	SeriesID               string   `json:"seriesID"`
	PodUID                 string   `json:"podUID,omitempty"`
	ObservedSeconds        float64  `json:"observedSeconds"`
	ThrottledSeconds       *float64 `json:"throttledSeconds,omitempty"`
	SecondsPerSecond       *float64 `json:"secondsPerSecond,omitempty"`
	Periods                *float64 `json:"periods,omitempty"`
	ThrottledPeriods       *float64 `json:"throttledPeriods,omitempty"`
	ThrottledPeriodPercent *float64 `json:"throttledPeriodPercent,omitempty"`
}
