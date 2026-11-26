// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"fmt"
	"math"
	"sort"
)

const (
	// ReasonCPUThrottlingPressure: verified same-release CFS counter intervals
	// show positive throttling, so a CPU limit reduction is held.
	ReasonCPUThrottlingPressure Reason = "cpu-throttling-pressure"
	// ReasonCPULimitBelowDemand: the proposed CPU limit is below recurring
	// measured demand times the CPU headroom coefficient.
	ReasonCPULimitBelowDemand Reason = "cpu-limit-below-recurring-demand"
)

const (
	ruleCPURecurringDemand        = "cpu limit covers recurring demand × headroom"
	ruleCPURecurringDemandUnknown = "cpu recurring demand unavailable"
	ruleCPUQuotaPressure          = "no repeated cpu quota pressure in fresh same-release lifetimes"
	ruleCPUQuotaPressureUnknown   = "cpu quota pressure unknown: no fresh verified same-release counter intervals"
	ruleCPUQuotaPressureUnproven  = "cpu quota pressure not repeated in fresh observed lifetimes; lifetime coverage unknown"
)

// cpuQuotaPressureMinIntervals is how many positive counter intervals one
// identified lifetime must show before throttling counts as pressure. A single
// tick or isolated increment never holds a reduction.
const cpuQuotaPressureMinIntervals = 2

// CPULimitReductionGuardPolicy opts in to holding the final material reduction
// of a known finite CPU limit. It never changes requests, memory, or limit
// increases/introductions. Absent, partial, stale, pre-release, foreign or
// malformed CFS counters never hold a reduction and are never treated as zero
// throttling. Throttling holds only on repeated positive intervals in one
// fresh, uniquely identified same-release lifetime.
type CPULimitReductionGuardPolicy struct {
	// RecurringSamples is how many observations of one container lifetime must
	// reach a demand level for it to count as recurring. Zero selects 3.
	RecurringSamples int `json:"recurringSamples"`
}

func normalizeCPULimitReductionGuard(g CPULimitReductionGuardPolicy) (CPULimitReductionGuardPolicy, error) {
	if g.RecurringSamples == 0 {
		g.RecurringSamples = 3
	}
	if g.RecurringSamples < 1 {
		return CPULimitReductionGuardPolicy{}, fmt.Errorf("cpu.limitReductionGuard.recurringSamples must be positive")
	}
	return g, nil
}

// cpuLimitReductionHold runs the two independent checks and returns the reasons
// that hold the candidate. Demand cannot see quota-suppressed demand, and
// throttling cannot see uncapped demand, so neither substitutes for the other.
func cpuLimitReductionHold(in Input, c ContainerObservation, obs ResourceObservation, headroom float64, g CPULimitReductionGuardPolicy, freshnessSeconds float64, candidate float64, trace *SettingTrace) []Reason {
	var held []Reason
	if demand, ok := recurringCPUDemand(in, c, obs, g.RecurringSamples); ok {
		required := demand * headroom
		if !finite(required) {
			required = math.MaxFloat64
		}
		passed := candidate >= required
		trace.guard(ruleCPURecurringDemand, passed, map[string]float64{"candidate": candidate, "recurringDemand": demand, "coefficient": headroom, "required": required, "recurringSamples": float64(g.RecurringSamples)})
		if !passed {
			held = append(held, ReasonCPULimitBelowDemand)
		}
	} else {
		trace.step(ruleCPURecurringDemandUnknown, map[string]float64{"recurringSamples": float64(g.RecurringSamples)})
	}
	pressure := cpuQuotaPressure(in, c, freshnessSeconds)
	values := map[string]float64{"freshLifetimes": float64(pressure.freshLifetimes), "staleLifetimes": float64(pressure.staleLifetimes), "pressuredLifetimes": float64(pressure.pressuredLifetimes), "isolatedLifetimes": float64(pressure.isolatedLifetimes), "positiveIntervals": float64(pressure.positiveIntervals), "minimumPositiveIntervals": cpuQuotaPressureMinIntervals, "freshnessSeconds": freshnessSeconds, "throttledPeriods": pressure.throttledPeriods, "throttledSeconds": pressure.throttledSeconds}
	switch {
	case pressure.pressuredLifetimes > 0:
		// Repeated positive intervals in one fresh lifetime: actual evidence.
		trace.guard(ruleCPUQuotaPressure, false, values)
		held = append(held, ReasonCPUThrottlingPressure)
	case pressure.freshLifetimes == 0:
		// No fresh verified counters: unknown, not a passed check and not zero.
		trace.step(ruleCPUQuotaPressureUnknown, values)
	default:
		// Fresh counters without repeated pressure are recorded, but the set of
		// running lifetimes (the denominator) is unknown, so this is not a pass.
		trace.step(ruleCPUQuotaPressureUnproven, values)
	}
	return held
}

// recurringCPUDemand uses the sizing conversion and current-release window of
// normalizeUsage. Per lifetime, demand is the RecurringSamples-th largest
// observation, so one isolated spike cannot hold a reduction.
func recurringCPUDemand(in Input, c ContainerObservation, obs ResourceObservation, k int) (float64, bool) {
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	demand, found := 0.0, false
	for _, s := range obs.Series {
		if s.WorkloadUID == "" || s.Release == "" || s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
			continue
		}
		values, err := NormalizeSamples(s, start, in.EvaluationTime)
		if err != nil || len(values) < k {
			continue
		}
		sorted := make([]float64, len(values))
		for i, v := range values {
			sorted[i] = v.Value
		}
		sort.Float64s(sorted)
		if v := sorted[len(sorted)-k]; !found || v > demand {
			demand, found = v, true
		}
	}
	return demand, found
}

type cpuQuotaPressureEvidence struct {
	freshLifetimes     int
	staleLifetimes     int
	pressuredLifetimes int
	isolatedLifetimes  int
	positiveIntervals  int
	throttledPeriods   float64
	throttledSeconds   float64
}

// cpuQuotaPressure classifies reset- and gap-aware counter intervals of
// uniquely identified current-release lifetimes. A lifetime is fresh only when
// its latest valid interval ends within freshnessSeconds of evaluation; it is
// pressured only with at least cpuQuotaPressureMinIntervals positive intervals.
// Malformed, duplicated, foreign, or out-of-window series are skipped, never
// errors; stale series are counted for the trace but never prove anything.
func cpuQuotaPressure(in Input, c ContainerObservation, freshnessSeconds float64) cpuQuotaPressureEvidence {
	var e cpuQuotaPressureEvidence
	if c.Classification == nil {
		return e
	}
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	fresh, stale, pressured, isolated := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	throttling := c.Classification.Throttling
	for kind, rows := range [][]Series{throttling.ThrottledPeriods, throttling.Seconds} {
		count := map[string]int{}
		for _, s := range rows {
			if s.WorkloadUID == c.Target.WorkloadUID && s.Release == c.Target.Release {
				count[s.ID]++
			}
		}
		total := &e.throttledPeriods
		if kind == 1 {
			total = &e.throttledSeconds
		}
		for _, s := range rows {
			if s.ID == "" || s.WorkloadUID == "" || s.Release == "" || s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release || count[s.ID] != 1 {
				continue
			}
			intervals, err := CounterIntervals(s, start, in.EvaluationTime)
			if err != nil || len(intervals) == 0 {
				continue
			}
			delta, rises, latest := 0.0, 0, intervals[0].End
			for _, v := range intervals {
				delta += v.Delta
				if v.Delta > 0 {
					rises++
				}
				latest = max(latest, v.End)
			}
			if !finite(delta) || !finite(*total+delta) {
				continue
			}
			// An old series says nothing about the quota the container runs
			// under now: require a fresh latest valid interval.
			if float64(in.EvaluationTime-latest)/1000 > freshnessSeconds {
				stale[s.ID] = true
				continue
			}
			fresh[s.ID] = true
			switch {
			case rises >= cpuQuotaPressureMinIntervals:
				pressured[s.ID] = true
				e.positiveIntervals += rises
				*total += delta
			case rises > 0:
				isolated[s.ID] = true
			}
		}
	}
	for id := range fresh {
		delete(stale, id)
	}
	for id := range pressured {
		delete(isolated, id)
	}
	e.freshLifetimes, e.staleLifetimes = len(fresh), len(stale)
	e.pressuredLifetimes, e.isolatedLifetimes = len(pressured), len(isolated)
	return e
}

func appendNotice(notices []Reason, r Reason) []Reason {
	for _, v := range notices {
		if v == r {
			return notices
		}
	}
	return append(notices, r)
}
