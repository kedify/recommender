// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

func DefaultPolicy() Policy {
	return Policy{
		CPU:      CPUPolicy{Strategy: CPUStrategyPercentile, Percentile: 95, HeadroomCoefficient: 3, LimitsToRequestsRatio: 5, Bounds: Bounds{Minimum: 20, Maximum: 64000, MinimumAbsoluteChange: 50, MinimumRelativeChange: .1}},
		Memory:   MemoryPolicy{Strategy: MemoryStrategyMax, HeadroomCoefficient: 1.2, OOMKilledCoefficient: 1.5, LimitsToRequestsRatio: 3, Bounds: Bounds{Minimum: 10 * 1024 * 1024, Maximum: 1024 * 1024 * 1024 * 1024, MinimumAbsoluteChange: 8 * 1024 * 1024, MinimumRelativeChange: .1}},
		Evidence: EvidencePolicy{MinimumHistorySeconds: 3600, MinimumSamples: 30, MinimumCoverage: .9, FreshnessSeconds: 300},
	}
}
func NormalizePolicy(p Policy) (Policy, error) {
	d := DefaultPolicy()
	p.CPU.Strategy = CPUStrategy(strings.ToLower(strings.TrimSpace(string(p.CPU.Strategy))))
	if p.CPU.Strategy == "" {
		p.CPU.Strategy = d.CPU.Strategy
	}
	if p.CPU.Strategy != CPUStrategyMax && p.CPU.Strategy != CPUStrategyPercentile {
		return Policy{}, fmt.Errorf("unsupported cpu.strategy %q", p.CPU.Strategy)
	}
	p.Memory.Strategy = MemoryStrategy(strings.ToLower(strings.TrimSpace(string(p.Memory.Strategy))))
	if p.Memory.Strategy == "" {
		p.Memory.Strategy = d.Memory.Strategy
	}
	if p.Memory.Strategy != MemoryStrategyMax {
		return Policy{}, fmt.Errorf("unsupported memory.strategy %q", p.Memory.Strategy)
	}
	if p.Memory.OOMKilledCoefficient == 0 {
		p.Memory.OOMKilledCoefficient = d.Memory.OOMKilledCoefficient
	}
	if !finite(p.Memory.OOMKilledCoefficient) || p.Memory.OOMKilledCoefficient < 1 {
		return Policy{}, fmt.Errorf("memory.oomKilledCoefficient must be finite and at least one")
	}
	if p.CPU.Percentile == 0 {
		p.CPU.Percentile = d.CPU.Percentile
	}
	if p.CPU.Strategy == CPUStrategyMax {
		p.CPU.Percentile = 0
	} else if !positive(p.CPU.Percentile) || p.CPU.Percentile >= 100 {
		return Policy{}, fmt.Errorf("cpu.percentile must be in (0,100); use max for p100")
	}
	for _, v := range []struct {
		h, r   *float64
		dh, dr float64
	}{{&p.CPU.HeadroomCoefficient, &p.CPU.LimitsToRequestsRatio, d.CPU.HeadroomCoefficient, d.CPU.LimitsToRequestsRatio}, {&p.Memory.HeadroomCoefficient, &p.Memory.LimitsToRequestsRatio, d.Memory.HeadroomCoefficient, d.Memory.LimitsToRequestsRatio}} {
		if *v.h == 0 {
			*v.h = v.dh
		}
		if *v.r == 0 {
			*v.r = v.dr
		}
		if !positive(*v.h) || !positive(*v.r) || *v.r < 1 {
			return Policy{}, fmt.Errorf("headroom must be positive and limit ratio must be at least one")
		}
	}
	for _, v := range []struct {
		b *Bounds
		d Bounds
	}{{&p.CPU.Bounds, d.CPU.Bounds}, {&p.Memory.Bounds, d.Memory.Bounds}} {
		if v.b.Minimum == 0 {
			v.b.Minimum = v.d.Minimum
		}
		if v.b.Maximum == 0 {
			v.b.Maximum = v.d.Maximum
		}
		if v.b.MinimumAbsoluteChange == 0 {
			v.b.MinimumAbsoluteChange = v.d.MinimumAbsoluteChange
		}
		if v.b.MinimumRelativeChange == 0 {
			v.b.MinimumRelativeChange = v.d.MinimumRelativeChange
		}
		if !positive(v.b.Minimum) || !positive(v.b.Maximum) || v.b.Maximum < v.b.Minimum || !positive(v.b.MinimumAbsoluteChange) || !positive(v.b.MinimumRelativeChange) {
			return Policy{}, fmt.Errorf("bounds must be finite, positive, and maximum >= minimum")
		}
	}
	e := &p.Evidence
	if e.MinimumHistorySeconds == 0 {
		e.MinimumHistorySeconds = d.Evidence.MinimumHistorySeconds
	}
	if e.MinimumSamples == 0 {
		e.MinimumSamples = d.Evidence.MinimumSamples
	}
	if e.MinimumCoverage == 0 {
		e.MinimumCoverage = d.Evidence.MinimumCoverage
	}
	if e.FreshnessSeconds == 0 {
		e.FreshnessSeconds = d.Evidence.FreshnessSeconds
	}
	if e.MinimumHistorySeconds < 1 || e.MinimumSamples < 2 || !positive(e.MinimumCoverage) || e.MinimumCoverage > 1 || e.FreshnessSeconds < 1 {
		return Policy{}, fmt.Errorf("invalid evidence policy")
	}
	if p.Memory.LeakDetection != nil {
		leak, err := normalizeMemoryLeakPolicy(*p.Memory.LeakDetection)
		if err != nil {
			return Policy{}, err
		}
		p.Memory.LeakDetection = &leak
	}
	return p, nil
}
func PolicyVersion(p Policy) (string, error) {
	p, err := NormalizePolicy(p)
	if err != nil {
		return "", err
	}
	return normalizedPolicyVersion(p), nil
}
func normalizedPolicyVersion(p Policy) string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return "v2:" + hex.EncodeToString(h[:])
}
func positive(x float64) bool { return x > 0 && finite(x) }
func finite(x float64) bool   { return !math.IsNaN(x) && !math.IsInf(x, 0) }

func Analyze(in Input, p Policy) (Output, error) {
	if in.SchemaVersion != InputSchemaVersion {
		return Output{}, fmt.Errorf("unsupported input schema version %q (expected %q)", in.SchemaVersion, InputSchemaVersion)
	}
	if in.WindowStart <= 0 || in.EvaluationTime <= in.WindowStart {
		return Output{}, fmt.Errorf("windowStart and evaluationTime must define a positive Unix-millisecond window")
	}
	p, err := NormalizePolicy(p)
	if err != nil {
		return Output{}, err
	}
	out := Output{SchemaVersion: OutputSchemaVersion, DetectorVersion: ResourceRightSizeDetectorVersion, PolicyVersion: normalizedPolicyVersion(p), EffectivePolicy: p, Results: make([]ResourceAnalysis, 0, len(in.Containers)*2)}
	containers := append([]ContainerObservation(nil), in.Containers...)
	for i, c := range containers {
		if c.Target.Namespace == "" || c.Target.Kind == "" || c.Target.Name == "" || c.Target.Container == "" {
			return Output{}, fmt.Errorf("containers[%d]: target namespace, kind, name, and container are required", i)
		}
		if c.Inventory.Eligible < 0 || c.Inventory.Observed < 0 || c.Inventory.Excluded < 0 {
			return Output{}, fmt.Errorf("containers[%d]: negative inventory count", i)
		}
	}
	sort.Slice(containers, func(i, j int) bool { return targetKey(containers[i].Target) < targetKey(containers[j].Target) })
	for i, c := range containers {
		if i > 0 && targetKey(c.Target) == targetKey(containers[i-1].Target) {
			return Output{}, fmt.Errorf("duplicate logical container target %q", targetKey(c.Target))
		}
		c = selectReleaseSegment(in, c)
		for _, r := range []Resource{ResourceMemory, ResourceCPU} {
			result, err := analyzeResource(in, c, r, p)
			if err != nil {
				return Output{}, fmt.Errorf("%s %s: %w", c.Target.Name, r, err)
			}
			if r == ResourceMemory && p.Memory.LeakDetection != nil {
				result.MemoryLeak = analyzeMemoryLeak(in, c, p, result)
				if result.MemoryLeak.Status == MemoryLeakPotential {
					result.Notices = append(result.Notices, ReasonPotentialMemoryLeak)
				}
			}
			out.Results = append(out.Results, result)
		}
	}
	return out, nil
}
func targetKey(t Target) string {
	return t.Namespace + "\x00" + t.Kind + "\x00" + t.Name + "\x00" + t.Container
}
func stale(ts int64, in Input, p EvidencePolicy) bool {
	return ts <= 0 || ts > in.EvaluationTime || float64(in.EvaluationTime-ts)/1000 > float64(p.FreshnessSeconds)
}
func addReason(q *DataQuality, r Reason) {
	for _, v := range q.Reasons {
		if v == r {
			return
		}
	}
	q.Reasons = append(q.Reasons, r)
}

func analyzeResource(in Input, c ContainerObservation, r Resource, p Policy) (ResourceAnalysis, error) {
	obs := c.Memory
	headroom, ratio, bounds, requestsOnly := p.Memory.HeadroomCoefficient, p.Memory.LimitsToRequestsRatio, p.Memory.Bounds, p.Memory.RequestsOnly
	if r == ResourceCPU {
		obs = c.CPU
		headroom, ratio, bounds, requestsOnly = p.CPU.HeadroomCoefficient, p.CPU.LimitsToRequestsRatio, p.CPU.Bounds, p.CPU.RequestsOnly
	}
	result := ResourceAnalysis{Target: c.Target, Resource: r, Evidence: ResourceEvidence{CurrentRequest: canonicalSignal(obs.CurrentRequest), CurrentLimit: canonicalSignal(obs.CurrentLimit), Identity: c.Identity, Inventory: c.Inventory}, DataQuality: DataQuality{Status: DataQualityAvailable, Reasons: []Reason{}}}
	result.DecisionTrace = &DecisionTrace{Version: "1", Settings: []SettingTrace{
		{Setting: SettingRequests, Disposition: "retained"}, {Setting: SettingLimits, Disposition: "retained"},
	}}
	trace := result.DecisionTrace
	requestTrace, limitTrace := &trace.Settings[0], &trace.Settings[1]
	q := &result.DataQuality
	identity := c.Identity
	switch {
	case identity.Ambiguous:
		addReason(q, ReasonAmbiguousIdentity)
	case !identity.Available || identity.WorkloadUID == "" || identity.Release == "":
		addReason(q, ReasonMissingIdentity)
	case identity.WorkloadUID != c.Target.WorkloadUID || identity.Release != c.Target.Release:
		addReason(q, ReasonAmbiguousIdentity)
	case stale(identity.Timestamp, in, p.Evidence) || identity.Timestamp < identity.ReleaseStartedAt:
		addReason(q, ReasonStaleIdentity)
	}
	if identity.ReleaseStartedAt <= 0 || identity.ReleaseStartedAt > in.EvaluationTime {
		addReason(q, ReasonUnknownReleaseStart)
	}
	identityBlocked := len(q.Reasons) > 0
	usage, confidence, observed, err := normalizeUsage(in, c, obs, r, p, q, &trace.Source)
	if err != nil {
		return ResourceAnalysis{}, err
	}
	if !identityBlocked && insufficientRolloutUsage(*q) {
		fallbackUsage, fallbackConfidence, fallbackQuality, fallback, fallbackErr := previousReleaseUsage(in, c, r, p, *q, trace)
		if fallbackErr != nil {
			return ResourceAnalysis{}, fallbackErr
		}
		if fallback != nil {
			usage, confidence, *q = fallbackUsage, fallbackConfidence, fallbackQuality
			result.RolloutFallback = fallback
			result.Notices = append(result.Notices, ReasonPreviousReleaseUsage)
		}
	}
	result.Evidence.AggregatedUsage = usage
	usageBlocked := len(q.Reasons) > 0
	oomLimitUnknown := false
	if r == ResourceMemory {
		kills, oomErr := selectOOMKills(in, c)
		if oomErr != nil {
			return ResourceAnalysis{}, oomErr
		}
		result.Evidence.OOMKills = kills
		if len(kills) > 0 {
			result.Notices = append(result.Notices, ReasonOOMKillDetected)
		}
		for _, kill := range kills {
			if kill.MemoryLimitBytes == 0 {
				oomLimitUnknown = true
			}
		}
	}
	requestOK, limitOK := true, true
	for _, s := range []struct {
		value        Signal
		missing, old Reason
		ok           *bool
	}{{obs.CurrentRequest, ReasonMissingRequest, ReasonStaleRequest, &requestOK}, {obs.CurrentLimit, ReasonMissingLimit, ReasonStaleLimit, &limitOK}} {
		if s.value.Available && (!finite(s.value.Value) || s.value.Value < 0) {
			return ResourceAnalysis{}, fmt.Errorf("current signal must be finite and nonnegative")
		}
		if s.value.Available && s.value.Unset && s.value.Value != 0 {
			return ResourceAnalysis{}, fmt.Errorf("unset current signal cannot have a numeric value")
		}
		if !s.value.Available {
			addReason(q, s.missing)
			*s.ok = false
		} else if stale(s.value.Timestamp, in, p.Evidence) || s.value.Timestamp < identity.ReleaseStartedAt {
			addReason(q, s.old)
			*s.ok = false
		}
	}
	if identity.ReleaseStartInferred {
		addReason(q, ReasonInferredReleaseStart)
	}
	inventoryOK := true
	switch {
	case !c.Inventory.Available:
		addReason(q, ReasonUnknownInventory)
		inventoryOK = false
	case stale(c.Inventory.Timestamp, in, p.Evidence) || c.Inventory.Timestamp < identity.ReleaseStartedAt:
		addReason(q, ReasonStaleInventory)
		inventoryOK = false
	case c.Inventory.Excluded > 0:
		addReason(q, ReasonExcludedContainers)
		inventoryOK = false
	case c.Inventory.Eligible <= 0 || c.Inventory.Observed != c.Inventory.Eligible || observed != c.Inventory.Eligible:
		addReason(q, ReasonIncompleteInventory)
		inventoryOK = false
	}
	if oomLimitUnknown {
		addReason(q, ReasonOOMLimitUnknown)
	}
	// OOM evidence can size memory independently of usage history. Keep the
	// missing-usage reasons as partial evidence, rather than inventing samples.
	rawSuggestedRequest := 0.0
	if !usageBlocked {
		rawSuggestedRequest = usage.Value * headroom
	}
	if !finite(rawSuggestedRequest) {
		return ResourceAnalysis{}, fmt.Errorf("suggested value overflow")
	}
	var adjustment *OOMAdjustment
	if !identityBlocked && requestOK && len(result.Evidence.OOMKills) > 0 {
		currentBase := obs.CurrentRequest.Value
		if limitOK && obs.CurrentLimit.Value > 0 {
			currentBase = obs.CurrentLimit.Value
		}
		value, oomErr := oomAdjustment(result.Evidence.OOMKills, rawSuggestedRequest, currentBase, p.Memory.OOMKilledCoefficient)
		if oomErr != nil {
			return ResourceAnalysis{}, oomErr
		}
		if value.OOMRequestFloorBytes > 0 {
			adjustment = &value
		}
	}
	if identityBlocked || !requestOK || (usageBlocked && adjustment == nil) {
		q.Status = DataQualityUnavailable
		result.NoActionReason = q.Reasons[0]
		requestTrace.stop("unavailable", q.Reasons...)
		limitTrace.stop("unavailable", q.Reasons...)
		return result, nil
	}
	if !usageBlocked {
		requestTrace.step("usage × headroom", map[string]float64{"usage": usage.Value, "coefficient": headroom, "candidate": rawSuggestedRequest})
	} else {
		confidence = 0 // There is no qualifying usage history to score.
		latest := result.Evidence.OOMKills[len(result.Evidence.OOMKills)-1]
		trace.Source = UsageSource{Release: c.Target.Release, PodUID: latest.PodUID, Timestamp: latest.Timestamp, Method: "OOM kill"}
		requestTrace.step("OOM sizing without usage history", nil)
	}
	if adjustment != nil {
		result.OOMAdjustment = adjustment
		rawSuggestedRequest = math.Max(rawSuggestedRequest, adjustment.OOMRequestFloorBytes)
		requestTrace.step("OOM floor", map[string]float64{"baseline": adjustment.BaselineRequestBytes, "floor": adjustment.OOMRequestFloorBytes, "candidate": rawSuggestedRequest, "coefficient": p.Memory.OOMKilledCoefficient})
	}
	suggestedRequest := math.Max(bounds.Minimum, math.Min(bounds.Maximum, rawSuggestedRequest))
	if usageBlocked {
		suggestedRequest = math.Max(suggestedRequest, obs.CurrentRequest.Value)
	}
	requestTrace.step("request bounds", map[string]float64{"before": rawSuggestedRequest, "minimum": bounds.Minimum, "maximum": bounds.Maximum, "candidate": suggestedRequest})
	requestBounded := suggestedRequest != rawSuggestedRequest
	boundsSuppressedAction := requestBounded && isMaterial(obs.CurrentRequest, rawSuggestedRequest, bounds) && !isMaterial(obs.CurrentRequest, suggestedRequest, bounds)
	if requestBounded {
		addReason(q, ReasonBounds)
	}
	var suggestedLimit float64
	if !requestsOnly {
		rawSuggestedLimit := suggestedRequest * ratio
		if !finite(rawSuggestedLimit) {
			return ResourceAnalysis{}, fmt.Errorf("suggested value overflow")
		}
		suggestedLimit = math.Max(suggestedRequest, math.Min(bounds.Maximum, rawSuggestedLimit))
		if usageBlocked && limitOK {
			suggestedLimit = math.Max(suggestedLimit, obs.CurrentLimit.Value)
		}
		limitTrace.step("request × limit ratio", map[string]float64{"request": suggestedRequest, "ratio": ratio, "candidate": rawSuggestedLimit})
		limitTrace.step("limit bounds", map[string]float64{"before": rawSuggestedLimit, "minimum": suggestedRequest, "maximum": bounds.Maximum, "candidate": suggestedLimit})
		limitBounded := suggestedLimit != rawSuggestedLimit
		boundsSuppressedAction = boundsSuppressedAction || limitOK && limitBounded && isMaterial(obs.CurrentLimit, rawSuggestedLimit, bounds) && !isMaterial(obs.CurrentLimit, suggestedLimit, bounds)
		if limitBounded {
			addReason(q, ReasonBounds)
		}
	}
	downsizeSuppressed := false
	for _, s := range []struct {
		setting      Setting
		current      Signal
		suggested    float64
		ok           bool
		missing, old Reason
	}{
		{SettingRequests, obs.CurrentRequest, suggestedRequest, requestOK, ReasonMissingRequest, ReasonStaleRequest},
		{SettingLimits, obs.CurrentLimit, suggestedLimit, limitOK && !requestsOnly, ReasonMissingLimit, ReasonStaleLimit},
	} {
		settingTrace := requestTrace
		if s.setting == SettingLimits {
			settingTrace = limitTrace
		}
		if !s.ok {
			if requestsOnly && s.setting == SettingLimits {
				settingTrace.stop("disabled", ReasonLimitDisabled)
			} else {
				settingTrace.stop("unavailable", s.missing)
				if s.current.Available {
					settingTrace.stop("unavailable", s.old)
				}
			}
			continue
		}
		if s.setting == SettingLimits {
			retainedRequest := obs.CurrentRequest.Value
			for _, rec := range result.Recommendations {
				if rec.Setting == SettingRequests {
					retainedRequest = rec.SuggestedValue
				}
			}
			settingTrace.guard("limit covers retained request", s.suggested >= retainedRequest, map[string]float64{"candidate": s.suggested, "retainedRequest": retainedRequest})
			if s.suggested < retainedRequest {
				settingTrace.stop("retained", ReasonBounds)
				addReason(q, ReasonBounds)
				boundsSuppressedAction = boundsSuppressedAction || isMaterial(s.current, s.suggested, bounds)
				continue
			}
		}
		if s.suggested < s.current.Value || (s.setting == SettingLimits && s.current.Value == 0) {
			settingTrace.guard("safe reduction or introduction of limit", inventoryOK && !oomLimitUnknown, nil)
		}
		if (s.suggested < s.current.Value || (s.setting == SettingLimits && s.current.Value == 0)) && (!inventoryOK || oomLimitUnknown) {
			for _, reason := range q.Reasons {
				if reason == ReasonUnknownInventory || reason == ReasonStaleInventory || reason == ReasonIncompleteInventory || reason == ReasonExcludedContainers || reason == ReasonOOMLimitUnknown {
					settingTrace.Reasons = append(settingTrace.Reasons, reason)
				}
			}
			downsizeSuppressed = downsizeSuppressed || isMaterial(s.current, s.suggested, bounds)
			continue
		}
		// Do not propose a request above a known retained limit.
		if s.setting == SettingRequests && limitOK && obs.CurrentLimit.Value > 0 {
			settingTrace.guard("request fits retained or changing limit", s.suggested <= obs.CurrentLimit.Value || (!requestsOnly && isMaterial(obs.CurrentLimit, suggestedLimit, bounds)), map[string]float64{"candidate": s.suggested, "currentLimit": obs.CurrentLimit.Value})
		}
		if s.setting == SettingRequests && limitOK && obs.CurrentLimit.Value > 0 && s.suggested > obs.CurrentLimit.Value && (requestsOnly || !isMaterial(obs.CurrentLimit, suggestedLimit, bounds)) {
			settingTrace.stop("retained", ReasonBounds)
			addReason(q, ReasonBounds)
			boundsSuppressedAction = boundsSuppressedAction || isMaterial(s.current, s.suggested, bounds)
			continue
		}
		material := isMaterial(s.current, s.suggested, bounds)
		if s.current.Unset {
			settingTrace.step("initialize unset setting", map[string]float64{"candidate": s.suggested})
		} else {
			values := map[string]float64{"current": s.current.Value, "candidate": s.suggested, "absoluteChange": math.Abs(s.suggested - s.current.Value), "minimumAbsoluteChange": bounds.MinimumAbsoluteChange, "minimumRelativeChange": bounds.MinimumRelativeChange}
			if s.current.Value > 0 {
				values["relativeChange"] = math.Abs(s.suggested-s.current.Value) / s.current.Value
			}
			settingTrace.guard("material change", material, values)
		}
		if material {
			settingTrace.stop("recommended")
			result.Recommendations = append(result.Recommendations, Recommendation{Setting: s.setting, CurrentValue: s.current.Value, CurrentUnset: s.current.Unset, SuggestedValue: s.suggested, Confidence: confidence})
		} else {
			settingTrace.stop("retained", ReasonNoMaterialChange)
		}
	}
	if requestsOnly {
		addReason(q, ReasonLimitDisabled)
	}
	if len(q.Reasons) > 0 {
		q.Status = DataQualityPartial
	}
	if len(result.Recommendations) == 0 {
		if downsizeSuppressed {
			for _, reason := range q.Reasons {
				if reason == ReasonUnknownInventory || reason == ReasonStaleInventory || reason == ReasonIncompleteInventory || reason == ReasonExcludedContainers || reason == ReasonOOMLimitUnknown {
					result.NoActionReason = reason
					break
				}
			}
		}
		if result.NoActionReason == "" && boundsSuppressedAction {
			result.NoActionReason = ReasonBounds
		}
		if result.NoActionReason == "" {
			result.NoActionReason = ReasonNoMaterialChange
			addReason(q, ReasonNoMaterialChange)
		}
	}
	return result, nil
}
func canonicalSignal(s Signal) Signal {
	if !s.Available {
		return Signal{}
	}
	return s
}
func isMaterial(current Signal, suggested float64, b Bounds) bool {
	if current.Unset {
		return suggested > 0
	}
	delta := math.Abs(current.Value - suggested)
	return delta > 0 && delta >= b.MinimumAbsoluteChange && (current.Value == 0 || delta/current.Value >= b.MinimumRelativeChange)
}

// A replica's percentile is computed separately; the largest replica result is
// used for the shared container setting. History spans the current release across
// pod lifetimes; new healthy replicas do not erase established release history.
func normalizeUsage(in Input, c ContainerObservation, obs ResourceObservation, r Resource, p Policy, q *DataQuality, source *UsageSource) (Signal, int, int, error) {
	*source = UsageSource{Release: c.Target.Release, Method: "maximum"}
	if r == ResourceCPU && p.CPU.Strategy == CPUStrategyPercentile {
		source.Method = "maximum of per-series nearest-rank percentiles"
		source.Percentile = p.CPU.Percentile
	}
	series := append([]Series(nil), obs.Series...)
	sort.Slice(series, func(i, j int) bool { return series[i].ID < series[j].ID })
	ids := map[string]bool{}
	pods := map[string]bool{}
	selected := 0
	aggregate := 0.0
	aggregateTimestamp := int64(0)
	aggregateConfidence := 0.0
	releaseTimes := []int64{}
	cadences := []float64{}
	start := in.WindowStart
	if c.Identity.ReleaseStartedAt > start {
		start = c.Identity.ReleaseStartedAt
	}
	for _, s := range series {
		if s.WorkloadUID == "" || s.Release == "" {
			addReason(q, ReasonUnknownSeriesIdentity)
			continue
		}
		if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
			continue
		}
		if s.ID == "" || ids[s.ID] {
			return Signal{}, 0, 0, fmt.Errorf("selected series must have distinct nonempty IDs")
		}
		ids[s.ID] = true
		if s.Kind != SampleGauge && s.Kind != SampleCPUCounterSeconds {
			return Signal{}, 0, 0, fmt.Errorf("unsupported sample kind %q", s.Kind)
		}
		if r == ResourceMemory && s.Kind != SampleGauge {
			return Signal{}, 0, 0, fmt.Errorf("memory samples must be byte gauges")
		}
		values, err := NormalizeSamples(s, start, in.EvaluationTime)
		if err != nil {
			return Signal{}, 0, 0, err
		}
		timestamps := make([]int64, len(values))
		for i, sample := range values {
			timestamps[i] = sample.Timestamp
		}
		if len(values) == 0 {
			continue
		}
		selected++
		pod := s.PodUID
		if pod == "" {
			pod = s.ID
		}
		if !stale(timestamps[len(timestamps)-1], in, p.Evidence) {
			pods[pod] = true
		}
		releaseTimes = append(releaseTimes, timestamps...)
		n := len(timestamps)
		q.SampleCount += n

		first, last := timestamps[0], timestamps[n-1]
		if q.ObservedStart == 0 || first < q.ObservedStart {
			q.ObservedStart = first
		}
		if last > q.ObservedEnd {
			q.ObservedEnd = last
		}
		gaps := []float64{}
		for i := 1; i < n; i++ {
			gaps = append(gaps, float64(timestamps[i]-timestamps[i-1])/1000)
		}
		cadence := 0.0
		if len(gaps) > 0 {
			sorted := append([]float64(nil), gaps...)
			sort.Float64s(sorted)
			cadence = sorted[(len(sorted)-1)/2]
			cadences = append(cadences, cadence)
		}
		sort.Slice(values, func(i, j int) bool {
			if values[i].Value == values[j].Value {
				return values[i].Timestamp < values[j].Timestamp
			}
			return values[i].Value < values[j].Value
		})
		value := values[len(values)-1]
		if r == ResourceCPU && p.CPU.Strategy == CPUStrategyPercentile {
			rank := int(math.Ceil(p.CPU.Percentile/100*float64(len(values)))) - 1
			if rank < 0 {
				rank = 0
			}
			value = values[rank]
			// Use the latest actual observation supplying this percentile value.
			for i := rank + 1; i < len(values) && values[i].Value == value.Value; i++ {
				value = values[i]
			}
		}
		// The release may have enough history while a new replica alone supplies
		// its sizing value. Keep eligibility release-wide but do not borrow
		// confidence from another replica with a lower aggregate.
		seriesCovered := cadence
		for _, gap := range gaps {
			seriesCovered += math.Min(gap, cadence)
		}
		seriesSpan := float64(last-first)/1000 + cadence
		seriesCoverage := 0.0
		if seriesSpan > 0 {
			seriesCoverage = math.Min(1, seriesCovered/seriesSpan)
		}
		seriesConfidence := 95 * math.Min(1, seriesSpan/float64(p.Evidence.MinimumHistorySeconds)) * seriesCoverage * math.Min(1, float64(n)/float64(p.Evidence.MinimumSamples))
		// Equal values use the strongest supporting series, then its latest
		// source timestamp, independent of input order.
		if value.Value > aggregate || selected == 1 || value.Value == aggregate && (seriesConfidence > aggregateConfidence || seriesConfidence == aggregateConfidence && value.Timestamp > aggregateTimestamp) {
			aggregate = value.Value
			aggregateTimestamp = value.Timestamp
			aggregateConfidence = seriesConfidence
			source.SeriesID, source.PodUID, source.Timestamp = s.ID, s.PodUID, value.Timestamp
		}
	}
	q.SeriesCount = selected
	if selected == 0 {
		addReason(q, ReasonMissingUsage)
		return Signal{}, 0, 0, nil
	}
	sort.Slice(releaseTimes, func(i, j int) bool { return releaseTimes[i] < releaseTimes[j] })
	unique := releaseTimes[:0]
	for _, ts := range releaseTimes {
		if len(unique) == 0 || unique[len(unique)-1] != ts {
			unique = append(unique, ts)
		}
	}
	cadence := 0.0
	if len(cadences) > 0 {
		sort.Float64s(cadences)
		cadence = cadences[len(cadences)/2]
		q.CadenceSeconds = cadence
	}
	covered := cadence
	for i := 1; i < len(unique); i++ {
		gap := float64(unique[i]-unique[i-1]) / 1000
		covered += math.Min(gap, cadence)
	}
	if in.EvaluationTime > start {
		q.Coverage = math.Min(1, covered/(float64(in.EvaluationTime-start)/1000))
	}
	q.ObservedIntervalHours = float64(q.ObservedEnd-q.ObservedStart) / 3600000
	minSpan := float64(q.ObservedEnd-q.ObservedStart)/1000 + cadence
	q.ObservationCount = len(unique)
	if stale(q.ObservedEnd, in, p.Evidence) {
		addReason(q, ReasonStaleUsage)
	}
	if minSpan < float64(p.Evidence.MinimumHistorySeconds) {
		addReason(q, ReasonInsufficientHistory)
	}
	if q.ObservationCount < p.Evidence.MinimumSamples {
		addReason(q, ReasonInsufficientSamples)
	}
	if q.Coverage < p.Evidence.MinimumCoverage {
		addReason(q, ReasonSparseCoverage)
	}
	confidence := int(math.Floor(95 * math.Min(1, minSpan/float64(p.Evidence.MinimumHistorySeconds)) * q.Coverage * math.Min(1, float64(q.ObservationCount)/float64(p.Evidence.MinimumSamples))))
	confidence = min(confidence, int(math.Floor(aggregateConfidence)))
	return Signal{Available: true, Value: aggregate, Timestamp: aggregateTimestamp}, confidence, len(pods), nil
}

// selectReleaseSegment derives a conservative observed segment boundary when
// the source has no activation event. Seeing B between two A runs excludes old A.
func selectReleaseSegment(in Input, c ContainerObservation) ContainerObservation {
	cutoff := in.WindowStart - 1
	for _, obs := range []ResourceObservation{c.CPU, c.Memory} {
		for _, s := range obs.Series {
			if s.WorkloadUID != c.Target.WorkloadUID || s.Release == "" || s.Release == c.Target.Release {
				continue
			}
			for _, v := range s.Samples {
				if v.Timestamp <= in.EvaluationTime && v.Timestamp > cutoff {
					cutoff = v.Timestamp
				}
			}
		}
	}
	boundary := int64(0)
	for _, obs := range []ResourceObservation{c.CPU, c.Memory} {
		for _, s := range obs.Series {
			if s.WorkloadUID != c.Target.WorkloadUID || s.Release != c.Target.Release {
				continue
			}
			for _, v := range s.Samples {
				if v.Timestamp > cutoff && v.Timestamp <= in.EvaluationTime && (boundary == 0 || v.Timestamp < boundary) {
					boundary = v.Timestamp
				}
			}
		}
	}
	// A verified current-rollout OOM also proves the rollout was active at
	// that instant, including containers that died before their first scrape.
	for _, kill := range c.OOMKills {
		if kill.WorkloadUID == c.Target.WorkloadUID && kill.Release == c.Target.Release && kill.Timestamp > cutoff && kill.Timestamp <= in.EvaluationTime && (boundary == 0 || kill.Timestamp < boundary) {
			boundary = kill.Timestamp
		}
	}
	if boundary == 0 && cutoff >= in.WindowStart {
		boundary = cutoff + 1
	}
	if c.Identity.ReleaseStartedAt == 0 {
		c.Identity.ReleaseStartedAt = boundary
		c.Identity.ReleaseStartInferred = true
	} else if cutoff >= c.Identity.ReleaseStartedAt && boundary > c.Identity.ReleaseStartedAt {
		c.Identity.ReleaseStartedAt = boundary
		c.Identity.ReleaseStartInferred = true
	}
	return c
}
