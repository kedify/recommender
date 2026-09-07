package analysis

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultMemoryHeadroomCoefficient = 1.2
	defaultCPUHeadroomCoefficient    = 3.0
	defaultCPUPercentile             = 95.0

	minimumMemoryBytes       = 10.0 * 1024.0 * 1024.0
	minimumCPUMillicores     = 20.0
	defaultCPULimitRatio     = 5.0
	defaultMemoryLimitRatio  = 3.0
	minimumConfidence        = 20.0
	maximumConfidence        = 95.0
	fullConfidenceHours      = 7 * 24
	minimumRelativeChange    = 0.1
	minimumMemoryAbsChange   = 8.0
	minimumCPUAbsoluteChange = 50.0
)

// DefaultPolicy returns the policy used by Dashboard API when no options are set.
func DefaultPolicy() Policy {
	return Policy{
		CPU: CPUPolicy{
			Strategy:              CPUStrategyPercentile,
			Percentile:            defaultCPUPercentile,
			HeadroomCoefficient:   defaultCPUHeadroomCoefficient,
			LimitsToRequestsRatio: defaultCPULimitRatio,
		},
		Memory: MemoryPolicy{
			Strategy:              MemoryStrategyMax,
			HeadroomCoefficient:   defaultMemoryHeadroomCoefficient,
			LimitsToRequestsRatio: defaultMemoryLimitRatio,
		},
	}
}

// NormalizePolicy applies defaults and validates caller-provided policy values.
func NormalizePolicy(policy Policy) (Policy, error) {
	defaults := DefaultPolicy()

	policy.CPU.Strategy = CPUStrategy(strings.ToLower(strings.TrimSpace(string(policy.CPU.Strategy))))
	if policy.CPU.Strategy == "" {
		policy.CPU.Strategy = defaults.CPU.Strategy
	}
	if policy.CPU.Strategy != CPUStrategyMax && policy.CPU.Strategy != CPUStrategyPercentile {
		return Policy{}, fmt.Errorf("cpu.strategy must be one of %q or %q", CPUStrategyMax, CPUStrategyPercentile)
	}
	if policy.CPU.HeadroomCoefficient == 0 {
		policy.CPU.HeadroomCoefficient = defaults.CPU.HeadroomCoefficient
	}
	if policy.CPU.LimitsToRequestsRatio == 0 {
		policy.CPU.LimitsToRequestsRatio = defaults.CPU.LimitsToRequestsRatio
	}
	if !isFinitePositive(policy.CPU.HeadroomCoefficient) {
		return Policy{}, fmt.Errorf("cpu.headroomCoefficient must be greater than 0")
	}
	if !isFinitePositive(policy.CPU.LimitsToRequestsRatio) || policy.CPU.LimitsToRequestsRatio < 1 {
		return Policy{}, fmt.Errorf("cpu.limitsToRequestsRatio must be greater than or equal to 1")
	}
	if policy.CPU.Strategy == CPUStrategyPercentile {
		if policy.CPU.Percentile == 0 {
			policy.CPU.Percentile = defaults.CPU.Percentile
		}
		if !isFinitePositive(policy.CPU.Percentile) || policy.CPU.Percentile >= 100 {
			return Policy{}, fmt.Errorf("cpu.percentile must be greater than 0 and less than 100; use cpu.strategy=max for p100")
		}
	} else {
		policy.CPU.Percentile = 0
	}

	policy.Memory.Strategy = MemoryStrategy(strings.ToLower(strings.TrimSpace(string(policy.Memory.Strategy))))
	if policy.Memory.Strategy == "" {
		policy.Memory.Strategy = defaults.Memory.Strategy
	}
	if policy.Memory.Strategy != MemoryStrategyMax {
		return Policy{}, fmt.Errorf("memory.strategy must be %q", MemoryStrategyMax)
	}
	if policy.Memory.HeadroomCoefficient == 0 {
		policy.Memory.HeadroomCoefficient = defaults.Memory.HeadroomCoefficient
	}
	if policy.Memory.LimitsToRequestsRatio == 0 {
		policy.Memory.LimitsToRequestsRatio = defaults.Memory.LimitsToRequestsRatio
	}
	if !isFinitePositive(policy.Memory.HeadroomCoefficient) {
		return Policy{}, fmt.Errorf("memory.headroomCoefficient must be greater than 0")
	}
	if !isFinitePositive(policy.Memory.LimitsToRequestsRatio) || policy.Memory.LimitsToRequestsRatio < 1 {
		return Policy{}, fmt.Errorf("memory.limitsToRequestsRatio must be greater than or equal to 1")
	}

	return policy, nil
}

// PolicyVersion returns the stable policy identity used in recommendation
// fingerprints. Equivalent defaulted policies return the same value.
func PolicyVersion(policy Policy) (string, error) {
	policy, err := NormalizePolicy(policy)
	if err != nil {
		return "", err
	}
	return normalizedPolicyVersion(policy), nil
}

func normalizedPolicyVersion(policy Policy) string {
	cpuStrategy := string(policy.CPU.Strategy)
	if policy.CPU.Strategy == CPUStrategyPercentile {
		cpuStrategy = "p" + formatFloat(policy.CPU.Percentile)
	}
	return fmt.Sprintf("cpu=%s,h=%s,r=%s;mem=%s,h=%s,r=%s",
		cpuStrategy,
		formatFloat(policy.CPU.HeadroomCoefficient),
		formatFloat(policy.CPU.LimitsToRequestsRatio),
		policy.Memory.Strategy,
		formatFloat(policy.Memory.HeadroomCoefficient),
		formatFloat(policy.Memory.LimitsToRequestsRatio),
	)
}

// Analyze calculates recommendations without querying or mutating external state.
func Analyze(input Input, policy Policy) (Output, error) {
	if input.SchemaVersion != InputSchemaVersion {
		return Output{}, fmt.Errorf("unsupported input schema version %q", input.SchemaVersion)
	}
	if input.ObservedIntervalHours <= 0 {
		return Output{}, fmt.Errorf("observedIntervalHours must be greater than 0")
	}

	effectivePolicy, err := NormalizePolicy(policy)
	if err != nil {
		return Output{}, err
	}

	output := Output{
		SchemaVersion:   OutputSchemaVersion,
		DetectorVersion: ResourceRightSizeDetectorVersion,
		PolicyVersion:   normalizedPolicyVersion(effectivePolicy),
		EffectivePolicy: effectivePolicy,
		Results:         make([]ResourceAnalysis, 0, len(input.Containers)*2),
	}
	containers := append([]ContainerObservation(nil), input.Containers...)
	sort.SliceStable(containers, func(i, j int) bool {
		return targetLess(containers[i].Target, containers[j].Target)
	})
	for i, container := range containers {
		if i > 0 && container.Target == containers[i-1].Target {
			return Output{}, fmt.Errorf("containers[%d]: duplicate target", i)
		}
		if err := validateObservation(container); err != nil {
			return Output{}, fmt.Errorf("containers[%d]: %w", i, err)
		}
		memory, err := analyzeResource(container.Target, ResourceMemory, container.Memory, input.ObservedIntervalHours, effectivePolicy.Memory.HeadroomCoefficient, effectivePolicy.Memory.LimitsToRequestsRatio, minimumMemoryBytes, minimumMemoryAbsChange)
		if err != nil {
			return Output{}, fmt.Errorf("containers[%d]: %w", i, err)
		}
		cpu, err := analyzeResource(container.Target, ResourceCPU, container.CPU, input.ObservedIntervalHours, effectivePolicy.CPU.HeadroomCoefficient, effectivePolicy.CPU.LimitsToRequestsRatio, minimumCPUMillicores, minimumCPUAbsoluteChange)
		if err != nil {
			return Output{}, fmt.Errorf("containers[%d]: %w", i, err)
		}
		output.Results = append(output.Results, memory, cpu)
	}
	return output, nil
}

func analyzeResource(target Target, resource Resource, evidence ResourceObservation, intervalHours int, headroom, limitRatio, minimum, minimumAbsoluteChange float64) (ResourceAnalysis, error) {
	evidence = normalizeSignals(evidence)
	result := ResourceAnalysis{
		Target:   target,
		Resource: resource,
		Evidence: evidence,
		DataQuality: DataQuality{
			Status:                DataQualityAvailable,
			ObservedIntervalHours: intervalHours,
		},
	}

	if !evidence.AggregatedUsage.Available {
		result.DataQuality.MissingSignals = append(result.DataQuality.MissingSignals, SignalAggregatedUsage)
	}
	if !evidence.CurrentRequest.Available {
		result.DataQuality.MissingSignals = append(result.DataQuality.MissingSignals, SignalCurrentRequest)
	}
	if !evidence.CurrentLimit.Available {
		result.DataQuality.MissingSignals = append(result.DataQuality.MissingSignals, SignalCurrentLimit)
	}
	if !evidence.AggregatedUsage.Available || !evidence.CurrentRequest.Available {
		result.DataQuality.Status = DataQualityUnavailable
		return result, nil
	}
	if !evidence.CurrentLimit.Available {
		result.DataQuality.Status = DataQualityPartial
	}

	suggestedRequest := math.Max(minimum, evidence.AggregatedUsage.Value*headroom)
	if math.IsNaN(suggestedRequest) || math.IsInf(suggestedRequest, 0) {
		return ResourceAnalysis{}, fmt.Errorf("%s suggested request is not finite", resource)
	}
	if !isMaterialChange(evidence.CurrentRequest.Value, suggestedRequest, minimumAbsoluteChange) {
		return result, nil
	}

	confidence := recommendationConfidence(intervalHours)
	result.Recommendations = append(result.Recommendations, Recommendation{
		Setting:        SettingRequests,
		CurrentValue:   evidence.CurrentRequest.Value,
		SuggestedValue: suggestedRequest,
		Confidence:     confidence,
	})

	if !evidence.CurrentLimit.Available {
		return result, nil
	}

	suggestedLimit := suggestedRequest * limitRatio
	if math.IsNaN(suggestedLimit) || math.IsInf(suggestedLimit, 0) {
		return ResourceAnalysis{}, fmt.Errorf("%s suggested limit is not finite", resource)
	}
	if isMaterialChange(evidence.CurrentLimit.Value, suggestedLimit, minimumAbsoluteChange) {
		result.Recommendations = append(result.Recommendations, Recommendation{
			Setting:        SettingLimits,
			CurrentValue:   evidence.CurrentLimit.Value,
			SuggestedValue: suggestedLimit,
			Confidence:     confidence,
		})
	}
	return result, nil
}

func isMaterialChange(current, suggested, minimumAbsoluteChange float64) bool {
	return math.Max(current, suggested)/math.Min(current, suggested) >= 1+minimumRelativeChange &&
		math.Abs(current-suggested) >= minimumAbsoluteChange
}

func recommendationConfidence(intervalHours int) int {
	return int(math.Max(minimumConfidence, float64(intervalHours)*maximumConfidence/fullConfidenceHours))
}

func normalizeSignals(observation ResourceObservation) ResourceObservation {
	if !observation.AggregatedUsage.Available {
		observation.AggregatedUsage.Value = 0
	}
	if !observation.CurrentRequest.Available {
		observation.CurrentRequest.Value = 0
	}
	if !observation.CurrentLimit.Available {
		observation.CurrentLimit.Value = 0
	}
	return observation
}

func targetLess(left, right Target) bool {
	if left.Namespace != right.Namespace {
		return left.Namespace < right.Namespace
	}
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.Container < right.Container
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func isFinitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validateObservation(observation ContainerObservation) error {
	if observation.Target.Namespace == "" || observation.Target.Kind == "" || observation.Target.Name == "" || observation.Target.Container == "" {
		return fmt.Errorf("target namespace, kind, name, and container are required")
	}
	if err := validateResourceObservation(ResourceCPU, observation.CPU); err != nil {
		return err
	}
	return validateResourceObservation(ResourceMemory, observation.Memory)
}

func validateResourceObservation(resource Resource, observation ResourceObservation) error {
	for _, signal := range []struct {
		name  SignalName
		value Signal
	}{
		{name: SignalAggregatedUsage, value: observation.AggregatedUsage},
		{name: SignalCurrentRequest, value: observation.CurrentRequest},
		{name: SignalCurrentLimit, value: observation.CurrentLimit},
	} {
		if signal.value.Available && (signal.value.Value < 0 || math.IsNaN(signal.value.Value) || math.IsInf(signal.value.Value, 0)) {
			return fmt.Errorf("%s %s must be a finite value greater than or equal to 0", resource, signal.name)
		}
	}
	return nil
}
