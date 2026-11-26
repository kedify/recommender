// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import "math"

// A growth hold needs a mature trend. Early advisory findings may rest on as
// few as four buckets; a hold needs at least six buckets in the fresh episode
// that actually supplied a baseline, not merely allocated bucket slots.
const memorySafetyMinimumUsableBuckets = 6

// knownLimitOOMKills keeps events whose finite limit at termination is known.
// Unknown events stay in the evidence and still block reductions, but their
// failed limit is never replaced by a later allocation or by usage.
func knownLimitOOMKills(kills []OOMKill) []OOMKill {
	known := make([]OOMKill, 0, len(kills))
	for _, kill := range kills {
		if kill.MemoryLimitBytes > 0 {
			known = append(known, kill)
		}
	}
	return known
}

// memoryGrowthHold reuses the leak detector to decide whether a material memory
// reduction, or a new finite memory limit, must wait. Only an ongoing (fresh, not OOM-terminated) episode of the
// selected release with mature, well-covered growth holds. Inferred release
// boundaries and previous-release fallback never hold. It does not gate on the
// advisory status or notice. With no explicit leak policy the defaults are
// evaluated privately. The returned analysis is non-nil only when the detector ran.
func memoryGrowthHold(in Input, c ContainerObservation, p Policy, resource ResourceAnalysis) (bool, *MemoryLeakAnalysis) {
	if c.Identity.ReleaseStartInferred || resource.RolloutFallback != nil {
		return false, nil
	}
	leakPolicy := p.Memory.LeakDetection
	if leakPolicy == nil {
		defaults, err := normalizeMemoryLeakPolicy(MemoryLeakPolicy{})
		if err != nil {
			return false, nil
		}
		leakPolicy = &defaults
	}
	evaluated := p
	evaluated.Memory.LeakDetection = leakPolicy
	leak := analyzeMemoryLeak(in, c, evaluated, resource)
	bucketSeconds := float64(leakPolicy.BucketDurationSeconds)
	minimum := max(memorySafetyMinimumUsableBuckets, int(math.Ceil(float64(leakPolicy.MinimumHistorySeconds)/bucketSeconds)))
	for _, e := range leak.Episodes {
		usable := int(math.Round(e.UsableHistoryHours * 3600 / bucketSeconds))
		if e.Status == MemoryLeakPotential && len(e.OOMKillIDs) == 0 && !stale(e.ObservedEnd, in, p.Evidence) && e.Coverage >= p.Evidence.MinimumCoverage && usable >= minimum {
			return true, leak
		}
	}
	return false, leak
}
