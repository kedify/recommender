// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"sort"
)

const (
	// ReasonCPUThrottlingPressure: verified same-release CFS counter intervals
	// show positive throttling, so a CPU limit reduction is held.
	ReasonCPUThrottlingPressure Reason = "cpu-throttling-pressure"
	// ReasonCPULimitBelowDemand: the proposed CPU limit is below recurring
	// measured demand times the CPU headroom coefficient.
	ReasonCPULimitBelowDemand Reason = "cpu-limit-below-recurring-demand"
	// ReasonCPULimitEvidenceIncomplete: strict coverage was requested but
	// recurring demand or CFS coverage of every current eligible Pod could not
	// be proven, so the cap change is held.
	ReasonCPULimitEvidenceIncomplete Reason = "cpu-limit-evidence-incomplete"
	ReasonCPUIncreaseNoPressure      Reason = "cpu-limit-increase-without-repeated-pressure"
	ReasonCPUIncreaseDemandUnknown   Reason = "cpu-limit-increase-amount-unproven"
)

const (
	ruleCPURecurringDemand        = "cpu limit covers recurring demand × headroom"
	ruleCPURecurringDemandUnknown = "cpu recurring demand unavailable"
	ruleCPUQuotaPressure          = "no repeated cpu quota pressure in fresh same-release lifetimes"
	ruleCPUQuotaPressureUnknown   = "cpu quota pressure unknown: no fresh verified same-release counter intervals"
	ruleCPUQuotaPressureUnproven  = "cpu quota pressure not repeated in fresh observed lifetimes; lifetime coverage unknown"
	ruleCPUThrottlingCoverage     = "cpu throttling coverage proven for every current eligible pod"
	ruleCPUQuotaMeasuredZero      = "no cpu quota throttling measured in verified spans of every current eligible pod"
	ruleCPUQuotaIsolated          = "cpu quota throttling isolated, not repeated, in verified spans of every current eligible pod"
)

// cpuQuotaPressureMinIntervals is how many positive counter intervals one
// identified lifetime must show before throttling counts as pressure. A single
// tick or isolated increment never holds a reduction.
const cpuQuotaPressureMinIntervals = 2

// CPULimitReductionGuardPolicy checks material CPU limit reductions against
// recurring demand and repeated throttling in fresh same-release lifetimes.
// Strict coverage also requires recurring demand to justify a new finite cap.
type CPULimitReductionGuardPolicy struct {
	// RecurringSamples is how many observations of one container lifetime must
	// reach a demand level for it to count as recurring. Zero selects 3.
	RecurringSamples int `json:"recurringSamples"`
	// RequireCompleteCoverage makes the guard strict: a reduction proceeds only
	// with credible recurring demand and fresh, aligned same-release CFS proof
	// for every current eligible Pod; anything missing holds it. Existing-only
	// cap advice always requires this proof, independently of the primary policy.
	RequireCompleteCoverage bool `json:"requireCompleteCoverage,omitempty"`
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

// cpuLimitChangeHold runs the two independent checks and returns the reasons
// that hold the candidate. Demand cannot see quota-suppressed demand, and
// throttling cannot see uncapped demand, so neither substitutes for the other.
func cpuLimitChangeHold(in Input, c ContainerObservation, capReleaseStart int64, policy CPUPolicy, freshnessSeconds float64, candidate float64, trace *SettingTrace) []Reason {
	g := *policy.LimitReductionGuard
	if policy.ExistingLimitsOnly {
		if capReleaseStart > c.Identity.ReleaseStartedAt {
			trace.guard("sized request belongs to the verified CPU quota release", false, map[string]float64{
				"sizingReleaseStart": float64(c.Identity.ReleaseStartedAt), "verifiedReleaseStart": float64(capReleaseStart),
			})
			return []Reason{ReasonCPULimitEvidenceIncomplete}
		}
		g.RequireCompleteCoverage = true
	}
	obs := c.CPU
	headroom := policy.HeadroomCoefficient
	var cov cpuThrottlingCoverageEvidence
	if g.RequireCompleteCoverage && obs.CurrentLimit.Value > 0 {
		cov = cpuThrottlingCoverage(in, c, obs, freshnessSeconds, policy.ExistingLimitsOnly)
	}
	if policy.ExistingLimitsOnly && candidate > obs.CurrentLimit.Value {
		return cpuLimitIncreaseHold(in, c, obs, policy, cov, freshnessSeconds, candidate, trace)
	}
	var held []Reason
	var demand float64
	var complete bool
	if g.RequireCompleteCoverage {
		demand, complete = strictRecurringCPUDemand(in, c, obs, g.RecurringSamples, freshnessSeconds, nil)
	} else {
		demand, complete = recurringCPUDemand(in, c, obs, g.RecurringSamples)
	}
	if complete {
		required := demand * headroom
		if !finite(required) {
			required = math.MaxFloat64
		}
		passed := candidate >= required
		trace.guard(ruleCPURecurringDemand, passed, map[string]float64{"candidate": candidate, "recurringDemand": demand, "coefficient": headroom, "required": required, "recurringSamples": float64(g.RecurringSamples)})
		if !passed {
			held = append(held, ReasonCPULimitBelowDemand)
		}
	} else if g.RequireCompleteCoverage {
		// Strict coverage cannot assume unmeasured demand fits the lower cap.
		trace.guard(ruleCPURecurringDemandUnknown, false, map[string]float64{"recurringSamples": float64(g.RecurringSamples)})
		held = appendNotice(held, ReasonCPULimitEvidenceIncomplete)
	} else {
		trace.step(ruleCPURecurringDemandUnknown, map[string]float64{"recurringSamples": float64(g.RecurringSamples)})
	}
	if obs.CurrentLimit.Unset || obs.CurrentLimit.Value == 0 {
		// An uncapped container has no CFS quota to verify. Its known demand
		// must still fit the first proposed limit.
		return held
	}
	pressure := cpuQuotaPressure(in, c, freshnessSeconds, cov.proven)
	values := map[string]float64{"freshLifetimes": float64(pressure.freshLifetimes), "staleLifetimes": float64(pressure.staleLifetimes), "pressuredLifetimes": float64(pressure.pressuredLifetimes), "isolatedLifetimes": float64(pressure.isolatedLifetimes), "positiveIntervals": float64(pressure.positiveIntervals), "minimumPositiveIntervals": cpuQuotaPressureMinIntervals, "freshnessSeconds": freshnessSeconds, "throttledPeriods": pressure.throttledPeriods, "throttledSeconds": pressure.throttledSeconds}
	switch {
	case pressure.pressuredLifetimes > 0:
		// Repeated positive intervals in one fresh lifetime: actual evidence.
		trace.guard(ruleCPUQuotaPressure, false, values)
		held = append(held, ReasonCPUThrottlingPressure)
	case cov.proven && len(cov.repeatedPods) > 0:
		// Verified spans repeat throttling the lifetime scan did not count: still
		// pressure, never reported as measured zero or isolated.
		trace.guard(ruleCPUQuotaPressure, false, cpuCoverageSpanValues(values, cov))
		held = append(held, ReasonCPUThrottlingPressure)
	case cov.proven && cov.spanThrottledPeriods == 0 && cov.spanThrottledSeconds == 0:
		// Every current eligible Pod has a verified span with a positive period
		// denominator and no throttling: measured zero, not unknown. A step, not
		// a pass: zero under the current cap says nothing about a lower one.
		trace.step(ruleCPUQuotaMeasuredZero, cpuCoverageSpanValues(values, cov))
	case cov.proven:
		trace.step(ruleCPUQuotaIsolated, cpuCoverageSpanValues(values, cov))
	case pressure.freshLifetimes == 0:
		// No fresh verified counters: unknown, not a passed check and not zero.
		trace.step(ruleCPUQuotaPressureUnknown, values)
	default:
		// Fresh counters without repeated pressure are recorded, but the set of
		// running lifetimes (the denominator) is unknown, so this is not a pass.
		trace.step(ruleCPUQuotaPressureUnproven, values)
	}
	if g.RequireCompleteCoverage {
		// Coverage is a precondition, not a safety verdict: zero throttling under
		// the current, higher cap says nothing about demand under a lower one.
		trace.guard(ruleCPUThrottlingCoverage, cov.proven, cov.coverageValues(freshnessSeconds))
		if !cov.proven {
			held = appendNotice(held, ReasonCPULimitEvidenceIncomplete)
		}
	}
	return held
}

// Throttling measures time or periods denied, not how many more cores are
// needed. A numeric raise needs both current repeated quota pressure and
// independently observed recurring demand on a pressured Pod. This can include
// measurements earlier in the same runtime while the quota was less restrictive.
func cpuLimitIncreaseHold(in Input, c ContainerObservation, obs ResourceObservation, p CPUPolicy, cov cpuThrottlingCoverageEvidence, freshness, candidate float64, trace *SettingTrace) []Reason {
	trace.guard(ruleCPUThrottlingCoverage, cov.proven, cov.coverageValues(freshness))
	if !cov.proven {
		return []Reason{ReasonCPULimitEvidenceIncomplete}
	}
	pressured := len(cov.repeatedPods) > 0
	trace.guard("repeated throttling at the current applied quota", pressured, cpuCoverageSpanValues(nil, cov))
	if !pressured {
		return []Reason{ReasonCPUIncreaseNoPressure}
	}
	demand, complete := strictRecurringCPUDemand(in, c, obs, p.LimitReductionGuard.RecurringSamples, freshness, cov.repeatedPods)
	if !complete {
		trace.guard(ruleCPURecurringDemandUnknown, false, nil)
		return []Reason{ReasonCPUIncreaseDemandUnknown, ReasonCPULimitEvidenceIncomplete}
	}
	supported := demand * p.HeadroomCoefficient
	// Demand at the current cap cannot quantify a raise. The policy estimate
	// may provide partial relief when measured demand exceeds it, but may not
	// materially exceed the independently measured headroom.
	passed := finite(supported) && demand > obs.CurrentLimit.Value && isMaterial(obs.CurrentLimit, demand, p.Bounds) &&
		(candidate <= supported || !isMaterial(Signal{Value: supported}, candidate, p.Bounds))
	trace.guard("recurring demand supports the proposed CPU limit increase", passed, map[string]float64{
		"currentLimit": obs.CurrentLimit.Value, "recurringDemand": demand, "coefficient": p.HeadroomCoefficient,
		"candidate": candidate, "minimumAbsoluteChange": p.Bounds.MinimumAbsoluteChange, "minimumRelativeChange": p.Bounds.MinimumRelativeChange,
	})
	if !passed {
		return []Reason{ReasonCPUIncreaseDemandUnknown}
	}
	return nil
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

// Strict demand needs recurring observations for every eligible Pod. A
// recent sample can establish that a Pod is present without proving its demand.
func strictRecurringCPUDemand(in Input, c ContainerObservation, obs ResourceObservation, count int, freshnessSeconds float64, selectedPods map[string]bool) (float64, bool) {
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	// Do not count observations from before the counter source proved that
	// this container lifetime was running. In particular, old usage must not
	// supply recurring samples for a replacement container in the same Pod.
	starts := make(map[string]int64)
	if c.Inventory.CurrentPods == nil && c.Classification != nil && c.Classification.Throttling.SourceComplete {
		throttling := c.Classification.Throttling
		for _, series := range throttling.Periods {
			if series.CPUGuardAdvisoryOnly || series.WorkloadUID != c.Target.WorkloadUID || series.Release != c.Target.Release ||
				!cpuCounterSeriesCurrent(series, start, in, freshnessSeconds, throttling.CoverageAt) {
				continue
			}
			var first int64
			for _, sample := range series.Samples {
				if sample.Timestamp >= start && sample.Timestamp <= in.EvaluationTime && (first == 0 || sample.Timestamp < first) {
					first = sample.Timestamp
				}
			}
			starts[series.PodUID] = max(starts[series.PodUID], first)
		}
	}
	seen := make(map[string]bool)
	var demand float64
	for _, series := range obs.Series {
		if series.CPUGuardAdvisoryOnly || series.WorkloadUID != c.Target.WorkloadUID || series.Release != c.Target.Release ||
			!cpuGuardSeriesFresh(series, start, in, freshnessSeconds) {
			continue
		}
		if series.PodUID == "" || seen[series.PodUID] {
			return 0, false
		}
		runtimeStart, current := c.Inventory.CurrentPods[series.PodUID]
		if c.Inventory.CurrentPods != nil {
			if !current {
				continue
			}
			// Membership alone cannot distinguish demand across a restart.
			if runtimeStart <= 0 {
				return 0, false
			}
		}
		boundary := max(start, starts[series.PodUID], runtimeStart)
		values, err := NormalizeSamples(series, boundary, in.EvaluationTime)
		if err != nil || len(values) < count {
			return 0, false
		}
		if boundary > max(start, runtimeStart) {
			// Legacy sources must supply enough observations after CFS began,
			// but a late first counter cannot erase measured recurring bursts.
			values, err = NormalizeSamples(series, max(start, runtimeStart), in.EvaluationTime)
			if err != nil {
				return 0, false
			}
		}
		seen[series.PodUID] = true
		if selectedPods != nil && !selectedPods[series.PodUID] {
			continue
		}
		slices.SortFunc(values, func(a, b Sample) int {
			return cmp.Compare(a.Value, b.Value)
		})
		demand = max(demand, values[len(values)-count].Value)
	}
	return demand, len(seen) > 0 && len(seen) == c.Inventory.Eligible
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
func cpuQuotaPressure(in Input, c ContainerObservation, freshnessSeconds float64, currentOnly bool) cpuQuotaPressureEvidence {
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
			if _, current := c.Inventory.CurrentPods[s.PodUID]; currentOnly &&
				(c.Inventory.CurrentPods != nil && !current || !cpuCounterSeriesCurrent(s, start, in, freshnessSeconds, throttling.CoverageAt)) {
				continue
			}
			if s.ID == "" || s.WorkloadUID == "" || s.Release == "" || s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release || count[s.ID] != 1 {
				continue
			}
			since := start
			if currentOnly {
				since = max(since, c.Inventory.CurrentPods[s.PodUID], s.CPUGuardStart)
			}
			intervals, err := counterIntervals(s, since, in.EvaluationTime, true)
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

// cpuCoverageMinIntervals is how many exactly aligned, adjacent, valid CFS
// intervals each eligible Pod's current lifetime needs for strict coverage.
const cpuCoverageMinIntervals = 2

type cpuThrottlingCoverageEvidence struct {
	sourceComplete       bool
	inventoryValid       bool
	eligiblePods         int
	expectedPods         int
	provenPods           int
	proven               bool
	throttledPods        int             // proven Pods with any throttling in their span
	repeatedPods         map[string]bool // proven Pods throttled in every span interval
	spanPeriods          float64         // summed period deltas (denominator) of the verified spans
	spanThrottledPeriods float64
	spanThrottledSeconds float64
}

func cpuGuardFlag(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (cov cpuThrottlingCoverageEvidence) coverageValues(freshnessSeconds float64) map[string]float64 {
	return map[string]float64{"sourceComplete": cpuGuardFlag(cov.sourceComplete), "inventoryValid": cpuGuardFlag(cov.inventoryValid), "eligiblePods": float64(cov.eligiblePods), "expectedPods": float64(cov.expectedPods), "provenPods": float64(cov.provenPods), "minimumAlignedIntervals": cpuCoverageMinIntervals, "freshnessSeconds": freshnessSeconds}
}

// cpuCoverageSpanValues adds aligned-span totals alongside the lifetime-scan
// totals, which only sum series with repeated pressure.
func cpuCoverageSpanValues(values map[string]float64, cov cpuThrottlingCoverageEvidence) map[string]float64 {
	out := make(map[string]float64, len(values)+6)
	for k, v := range values {
		out[k] = v
	}
	out["provenPods"] = float64(cov.provenPods)
	out["throttledPods"] = float64(cov.throttledPods)
	out["repeatedPods"] = float64(len(cov.repeatedPods))
	out["spanPeriods"] = cov.spanPeriods
	out["spanThrottledPeriods"] = cov.spanThrottledPeriods
	out["spanThrottledSeconds"] = cov.spanThrottledSeconds
	return out
}

func cpuGuardFresh(ts int64, in Input, freshnessSeconds float64) bool {
	return ts > 0 && ts <= in.EvaluationTime && float64(in.EvaluationTime-ts)/1000 <= freshnessSeconds
}

func cpuGuardSeriesFresh(series Series, start int64, in Input, freshnessSeconds float64) bool {
	return slices.ContainsFunc(series.Samples, func(sample Sample) bool {
		return sample.Timestamp >= start && cpuGuardFresh(sample.Timestamp, in, freshnessSeconds)
	})
}

func cpuCounterSeriesCurrent(series Series, start int64, in Input, freshnessSeconds float64, coverageAt int64) bool {
	if series.CPUGuardAdvisoryOnly {
		return false
	}
	if coverageAt == 0 {
		return cpuGuardSeriesFresh(series, start, in, freshnessSeconds)
	}
	return coverageAt >= start && cpuGuardFresh(coverageAt, in, freshnessSeconds) &&
		slices.ContainsFunc(series.Samples, func(sample Sample) bool { return sample.Timestamp == coverageAt })
}

// cpuThrottlingCoverage proves CFS coverage for every current eligible Pod.
// The expected set is the fresh same-release CPU usage PodUIDs, trusted only
// with the adapter's SourceComplete flag, a fresh complete inventory without
// exclusions whose eligible count matches, and nonempty unique PodUIDs. Each
// expected Pod needs exactly one runtime lifetime per CFS family, all sharing
// one series ID, with a fresh aligned adjacent span (cpuCoverageSpan). All
// joins are map lookups; nothing is compared pairwise.
func cpuThrottlingCoverage(in Input, c ContainerObservation, obs ResourceObservation, freshnessSeconds float64, requireAppliedQuota bool) cpuThrottlingCoverageEvidence {
	inv := c.Inventory
	start := max(in.WindowStart, c.Identity.ReleaseStartedAt)
	e := cpuThrottlingCoverageEvidence{eligiblePods: inv.Eligible, repeatedPods: make(map[string]bool)}
	if c.Classification == nil || !c.Classification.Throttling.SourceComplete {
		return e
	}
	e.sourceComplete = true
	if c.Target.WorkloadUID == "" || c.Target.Release == "" || !inv.Available || inv.Eligible <= 0 || inv.Observed != inv.Eligible || inv.Excluded != 0 || inv.CurrentPods != nil && len(inv.CurrentPods) != inv.Eligible || inv.Timestamp < start || !cpuGuardFresh(inv.Timestamp, in, freshnessSeconds) {
		return e
	}
	e.inventoryValid = true
	type usageSpan struct{ start, end int64 }
	expected := map[string]usageSpan{}
	for _, s := range obs.Series {
		if s.CPUGuardAdvisoryOnly || s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
			continue
		}
		values, err := NormalizeSamples(s, start, in.EvaluationTime)
		if err != nil || len(values) == 0 {
			continue
		}
		// NormalizeSamples orders observations by source time.
		latest := values[len(values)-1].Timestamp
		if !cpuGuardFresh(latest, in, freshnessSeconds) {
			continue
		}
		if _, current := inv.CurrentPods[s.PodUID]; inv.CurrentPods != nil && !current {
			continue
		}
		if _, duplicate := expected[s.PodUID]; s.PodUID == "" || duplicate {
			// An unattributable or repeated Pod makes the expected set unreliable.
			return e
		}
		usage := usageSpan{start: latest, end: latest}
		if requireAppliedQuota && s.Kind == SampleCPUCounterSeconds {
			// A rate also depends on the previous distinct raw reading.
			usage.start = 0
			for _, sample := range s.Samples {
				if sample.Timestamp < latest {
					usage.start = max(usage.start, sample.Timestamp)
				}
			}
		}
		expected[s.PodUID] = usage
	}
	e.expectedPods = len(expected)
	if e.expectedPods != inv.Eligible {
		return e
	}
	throttling := c.Classification.Throttling
	var byPod [3]map[string]Series
	for f, rows := range [3][]Series{throttling.Periods, throttling.ThrottledPeriods, throttling.Seconds} {
		byPod[f] = make(map[string]Series, len(expected))
		podOf := map[string]string{}
		for _, s := range rows {
			if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release ||
				!cpuCounterSeriesCurrent(s, start, in, freshnessSeconds, throttling.CoverageAt) {
				continue
			}
			if s.ID == "" || s.PodUID == "" {
				return e
			}
			if _, dup := byPod[f][s.PodUID]; dup {
				// Overlapping candidate runtime IDs for one Pod are ambiguous.
				return e
			}
			if pod, seen := podOf[s.ID]; seen && pod != s.PodUID {
				return e
			}
			podOf[s.ID] = s.PodUID
			byPod[f][s.PodUID] = s
		}
	}
	// Sorted so the float span totals in the trace are deterministic.
	pods := make([]string, 0, len(expected))
	for pod := range expected {
		pods = append(pods, pod)
	}
	sort.Strings(pods)
	for _, pod := range pods {
		p, okP := byPod[0][pod]
		th, okT := byPod[1][pod]
		sec, okS := byPod[2][pod]
		runtimeStart := inv.CurrentPods[pod]
		if !okP || !okT || !okS || p.ID != th.ID || p.ID != sec.ID || inv.CurrentPods != nil && runtimeStart <= 0 {
			continue
		}
		if requireAppliedQuota && (runtimeStart <= 0 || min(p.CPUGuardStart, th.CPUGuardStart, sec.CPUGuardStart) <= 0) {
			continue
		}
		quotaStart := max(start, runtimeStart, p.CPUGuardStart, th.CPUGuardStart, sec.CPUGuardStart)
		span, ok := cpuCoverageSpan(p, th, sec, quotaStart, in, freshnessSeconds, throttling.CoverageAt)
		usage := expected[pod]
		if !ok || requireAppliedQuota && (usage.start < quotaStart || usage.end < span.start) {
			continue
		}
		e.provenPods++
		e.spanPeriods += span.periods
		e.spanThrottledPeriods += span.throttledPeriods
		e.spanThrottledSeconds += span.throttledSeconds
		if span.throttledPeriods > 0 || span.throttledSeconds > 0 {
			e.throttledPods++
		}
		if span.throttledRises >= cpuQuotaPressureMinIntervals || span.secondsRises >= cpuQuotaPressureMinIntervals {
			e.repeatedPods[pod] = true
		}
	}
	// The span totals are the denominator behind a measured-zero or isolated
	// verdict: a zero, NaN or overflowed denominator is never proof.
	e.proven = e.provenPods == e.expectedPods && e.spanPeriods > 0 && finite(e.spanPeriods) && finite(e.spanThrottledPeriods) && finite(e.spanThrottledSeconds)
	return e
}

// cpuCoverageSpan requires the latest periods interval to be fresh and the
// newest cpuCoverageMinIntervals intervals to be adjacent (no gap or reset
// between them) and exactly aligned across all three families, each with a
// positive period denominator, throttled periods <= periods, and finite
// non-negative throttled seconds. It returns the paired deltas of exactly
// those verified intervals.
func cpuCoverageSpan(periods, throttled, seconds Series, start int64, in Input, freshnessSeconds float64, coverageAt int64) (cpuCoverageSpanTotals, bool) {
	type span struct{ start, end int64 }
	p, err := CounterIntervals(periods, start, in.EvaluationTime)
	if err != nil || len(p) < cpuCoverageMinIntervals {
		return cpuCoverageSpanTotals{}, false
	}
	index := func(s Series) map[span]float64 {
		intervals, err := CounterIntervals(s, start, in.EvaluationTime)
		if err != nil {
			return nil
		}
		out := make(map[span]float64, len(intervals))
		for _, v := range intervals {
			out[span{v.Start, v.End}] = v.Delta
		}
		return out
	}
	th, sec := index(throttled), index(seconds)
	latest := p[len(p)-1]
	if !cpuGuardFresh(latest.End, in, freshnessSeconds) || coverageAt != 0 && latest.End != coverageAt {
		return cpuCoverageSpanTotals{}, false
	}
	// CounterIntervals omits resets and gaps. The proof must reach the newest
	// observation in all three families, including a terminal reset or gap.
	for _, series := range []Series{periods, throttled, seconds} {
		if slices.ContainsFunc(series.Samples, func(sample Sample) bool {
			return sample.Timestamp > latest.End && sample.Timestamp <= in.EvaluationTime
		}) {
			return cpuCoverageSpanTotals{}, false
		}
	}
	var t cpuCoverageSpanTotals
	next := latest.End
	for i := len(p) - 1; i >= len(p)-cpuCoverageMinIntervals; i-- {
		v := p[i]
		if v.End != next {
			return cpuCoverageSpanTotals{}, false
		}
		k := span{v.Start, v.End}
		dt, okT := th[k]
		ds, okS := sec[k]
		if !okT || !okS || !(v.Delta > 0) || !finite(v.Delta) || !finite(dt) || dt < 0 || dt > v.Delta || !finite(ds) || ds < 0 {
			return cpuCoverageSpanTotals{}, false
		}
		// Paired deltas of one verified interval with a positive denominator:
		// zero throttling here is measured, not missing.
		t.periods += v.Delta
		t.throttledPeriods += dt
		t.throttledSeconds += ds
		if dt > 0 {
			t.throttledRises++
		}
		if ds > 0 {
			t.secondsRises++
		}
		next = v.Start
	}
	t.start = next
	return t, true
}

// cpuCoverageSpanTotals are the paired CFS deltas of one Pod's verified span.
type cpuCoverageSpanTotals struct {
	start            int64
	periods          float64
	throttledPeriods float64
	throttledSeconds float64
	throttledRises   int
	secondsRises     int
}

func appendNotice(notices []Reason, r Reason) []Reason {
	for _, v := range notices {
		if v == r {
			return notices
		}
	}
	return append(notices, r)
}
