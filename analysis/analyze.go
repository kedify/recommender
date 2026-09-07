package analysis

import (
	"fmt"
	"math"
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
	if policy.CPU.HeadroomCoefficient <= 0 {
		return Policy{}, fmt.Errorf("cpu.headroomCoefficient must be greater than 0")
	}
	if policy.CPU.LimitsToRequestsRatio <= 0 {
		return Policy{}, fmt.Errorf("cpu.limitsToRequestsRatio must be greater than 0")
	}
	if policy.CPU.Strategy == CPUStrategyPercentile {
		if policy.CPU.Percentile == 0 {
			policy.CPU.Percentile = defaults.CPU.Percentile
		}
		if policy.CPU.Percentile <= 0 || policy.CPU.Percentile >= 100 {
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
	if policy.Memory.HeadroomCoefficient <= 0 {
		return Policy{}, fmt.Errorf("memory.headroomCoefficient must be greater than 0")
	}
	if policy.Memory.LimitsToRequestsRatio <= 0 {
		return Policy{}, fmt.Errorf("memory.limitsToRequestsRatio must be greater than 0")
	}

	return policy, nil
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
		EffectivePolicy: effectivePolicy,
		Results:         make([]ResourceAnalysis, 0, len(input.Containers)*2),
	}
	for i, container := range input.Containers {
		if err := validateObservation(container); err != nil {
			return Output{}, fmt.Errorf("containers[%d]: %w", i, err)
		}
		output.Results = append(output.Results,
			analyzeResource(container.Target, ResourceMemory, container.Memory, input.ObservedIntervalHours, effectivePolicy.Memory.HeadroomCoefficient, effectivePolicy.Memory.LimitsToRequestsRatio, minimumMemoryBytes, minimumMemoryAbsChange),
			analyzeResource(container.Target, ResourceCPU, container.CPU, input.ObservedIntervalHours, effectivePolicy.CPU.HeadroomCoefficient, effectivePolicy.CPU.LimitsToRequestsRatio, minimumCPUMillicores, minimumCPUAbsoluteChange),
		)
	}
	return output, nil
}

func analyzeResource(target Target, resource Resource, evidence ResourceObservation, intervalHours int, headroom, limitRatio, minimum, minimumAbsoluteChange float64) ResourceAnalysis {
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
	if len(result.DataQuality.MissingSignals) != 0 {
		result.DataQuality.Status = DataQualityUnavailable
		return result
	}

	suggestedRequest := math.Max(minimum, evidence.AggregatedUsage.Value*headroom)
	if !isMaterialChange(evidence.CurrentRequest.Value, suggestedRequest, minimumAbsoluteChange) {
		return result
	}

	confidence := int(math.Max(minimumConfidence, float64(intervalHours)*maximumConfidence/fullConfidenceHours))
	result.Recommendations = append(result.Recommendations, Recommendation{
		Setting:        SettingRequests,
		CurrentValue:   evidence.CurrentRequest.Value,
		SuggestedValue: suggestedRequest,
		Confidence:     confidence,
	})

	if !evidence.CurrentLimit.Available {
		result.DataQuality.Status = DataQualityPartial
		result.DataQuality.MissingSignals = []SignalName{SignalCurrentLimit}
		return result
	}

	suggestedLimit := suggestedRequest * limitRatio
	if isMaterialChange(evidence.CurrentLimit.Value, suggestedLimit, minimumAbsoluteChange) {
		result.Recommendations = append(result.Recommendations, Recommendation{
			Setting:        SettingLimits,
			CurrentValue:   evidence.CurrentLimit.Value,
			SuggestedValue: suggestedLimit,
			Confidence:     confidence,
		})
	}
	return result
}

func isMaterialChange(current, suggested, minimumAbsoluteChange float64) bool {
	return math.Max(current, suggested)/math.Min(current, suggested) >= 1+minimumRelativeChange &&
		math.Abs(current-suggested) >= minimumAbsoluteChange
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
