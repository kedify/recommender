// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"fmt"
	"math"
	"sort"
)

// Select by event time, not observation freshness: a historical kill remains
// relevant throughout the selected release segment, even after its pod is gone.
func selectOOMKills(in Input, c ContainerObservation) ([]OOMKill, error) {
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	var kills []OOMKill
	seen := make(map[string]OOMKill)
	for _, kill := range c.OOMKills {
		if kill.Timestamp <= 0 {
			return nil, fmt.Errorf("OOM kill timestamp must be positive Unix milliseconds")
		}
		if kill.Timestamp < start || kill.Timestamp > in.EvaluationTime {
			continue
		}
		if kill.WorkloadUID == "" || kill.Release == "" {
			return nil, fmt.Errorf("OOM kill workload UID and release are required")
		}
		if kill.WorkloadUID != c.Target.WorkloadUID || kill.Release != c.Target.Release {
			continue
		}
		if kill.ID == "" {
			return nil, fmt.Errorf("OOM kill ID is required")
		}
		if !finite(kill.MemoryLimitBytes) || kill.MemoryLimitBytes < 0 {
			return nil, fmt.Errorf("OOM kill memory limit must be finite and nonnegative")
		}
		if previous, ok := seen[kill.ID]; ok {
			if previous != kill {
				return nil, fmt.Errorf("conflicting observations for OOM kill %q", kill.ID)
			}
			continue
		}
		seen[kill.ID] = kill
		kills = append(kills, kill)
	}
	sort.Slice(kills, func(i, j int) bool {
		if kills[i].Timestamp != kills[j].Timestamp {
			return kills[i].Timestamp < kills[j].Timestamp
		}
		return kills[i].ID < kills[j].ID
	})
	return kills, nil
}

func oomAdjustment(kills []OOMKill, baseline, currentBase, coefficient float64) (OOMAdjustment, error) {
	adjustment := OOMAdjustment{BaselineRequestBytes: baseline}
	for _, kill := range kills {
		base := kill.MemoryLimitBytes
		if base == 0 {
			base = currentBase
			if base > 0 {
				adjustment.UsedCurrentFallback = true
			} else {
				base = baseline
				adjustment.UsedUsageFallback = true
			}
		}
		floor := base * coefficient
		if !finite(floor) {
			return OOMAdjustment{}, fmt.Errorf("OOM suggested value overflow")
		}
		// Repeated kills do not compound the increase. The strongest event wins.
		adjustment.OOMRequestFloorBytes = math.Max(adjustment.OOMRequestFloorBytes, floor)
	}
	return adjustment, nil
}
