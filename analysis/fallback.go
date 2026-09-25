// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

const ReasonPreviousReleaseUsage Reason = "previous-release-usage"

// Fallback replaces only usage evidence. In particular, historical pod counts
// cannot stand in for the current inventory's freshly observed pods.
func insufficientRolloutUsage(q DataQuality) bool {
	insufficient := false
	for _, reason := range q.Reasons {
		if reason == ReasonUnknownSeriesIdentity {
			return false
		}
		if reason == ReasonMissingUsage || reason == ReasonInsufficientHistory || reason == ReasonInsufficientSamples {
			insufficient = true
		}
	}
	return insufficient
}

func previousReleaseUsage(in Input, c ContainerObservation, resource Resource, p Policy, current DataQuality, trace *DecisionTrace) (Signal, int, DataQuality, *RolloutFallback, error) {
	seen := map[string]bool{c.Target.Release: true}
	for _, previous := range c.PreviousReleases[:min(MaxPreviousReleases, len(c.PreviousReleases))] {
		if previous.Release == "" || seen[previous.Release] {
			continue
		}
		seen[previous.Release] = true
		pastIn := in
		pastIn.EvaluationTime = min(previous.EvaluationTime, in.EvaluationTime, c.Identity.ReleaseStartedAt)
		if pastIn.EvaluationTime <= in.WindowStart {
			trace.Fallbacks = append(trace.Fallbacks, FallbackAttempt{Release: previous.Release, Reasons: []Reason{ReasonMissingUsage}})
			continue
		}
		past := c
		past.Target.Release = previous.Release
		past.Identity.Release = previous.Release
		past.Identity.ReleaseStartedAt = previous.ReleaseStartedAt
		past.Identity.ReleaseStartInferred = false
		past.CPU.Series, past.Memory.Series = previous.CPU, previous.Memory
		past = selectReleaseSegment(pastIn, past)
		obs := past.Memory
		if resource == ResourceCPU {
			obs = past.CPU
		}
		quality := DataQuality{Status: DataQualityAvailable, Reasons: []Reason{}}
		var source UsageSource
		usage, confidence, _, err := normalizeUsage(pastIn, past, obs, resource, p, &quality, &source)
		if err != nil {
			return Signal{}, 0, DataQuality{}, nil, err
		}
		if !usage.Available || len(quality.Reasons) != 0 {
			trace.Fallbacks = append(trace.Fallbacks, FallbackAttempt{Release: previous.Release, Reasons: append([]Reason(nil), quality.Reasons...)})
			continue
		}
		trace.Source = source
		trace.Fallbacks = append(trace.Fallbacks, FallbackAttempt{Release: previous.Release, Selected: true})
		current.Status = DataQualityUnavailable
		fallback := &RolloutFallback{
			Release: previous.Release, ReleaseStartedAt: past.Identity.ReleaseStartedAt,
			ReleaseStartInferred: past.Identity.ReleaseStartInferred,
			EvaluationTime:       pastIn.EvaluationTime, CurrentDataQuality: current,
		}
		return usage, confidence, quality, fallback, nil
	}
	return Signal{}, 0, DataQuality{}, nil, nil
}
