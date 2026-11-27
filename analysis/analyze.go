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
	"slices"
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
	if p.CPU.LimitReductionGuard != nil {
		guard, err := normalizeCPULimitReductionGuard(*p.CPU.LimitReductionGuard)
		if err != nil {
			return Policy{}, err
		}
		p.CPU.LimitReductionGuard = &guard
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
		if c.Identity.UsageStart < 0 || c.Identity.UsageStart > in.EvaluationTime || c.OOMCoverageStart < 0 || c.OOMCoverageStart > in.EvaluationTime {
			return Output{}, fmt.Errorf("containers[%d]: invalid coverage start", i)
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
		original := c
		if p.Memory.SafetyGuards && c.Classification != nil {
			// Once an adapter observes an identified OOM, sizing and classification
			// use the same event. Event selection reconciles repeated snapshots.
			c.OOMKills = slices.Concat(c.OOMKills, c.Classification.OOMKills)
		}
		c, err = selectEvidence(in, c, p.Memory.SafetyGuards || p.CPU.LimitReductionGuard != nil && p.CPU.LimitReductionGuard.RequireCompleteCoverage)
		if err != nil {
			return Output{}, fmt.Errorf("%s OOM evidence: %w", original.Target.Name, err)
		}
		usageIn := in
		usageIn.WindowStart = max(in.WindowStart, c.Identity.UsageStart)
		for _, r := range []Resource{ResourceMemory, ResourceCPU} {
			result, err := analyzeResource(usageIn, c, r, p)
			if err != nil {
				return Output{}, fmt.Errorf("%s %s: %w", c.Target.Name, r, err)
			}
			if r == ResourceMemory && p.Memory.LeakDetection != nil {
				// Memory safety guards may already have evaluated this explicit policy.
				if result.MemoryLeak == nil {
					result.MemoryLeak = analyzeMemoryLeak(usageIn, c, p, result)
				}
				if result.MemoryLeak.Status == MemoryLeakPotential {
					result.Notices = append(result.Notices, ReasonPotentialMemoryLeak)
				}
			}
			out.Results = append(out.Results, result)
		}
		if p.Classification != nil {
			if !p.Memory.SafetyGuards {
				// Legacy classification selects its own segment from its broader inputs.
				if original.Classification != nil {
					original.OOMKills = slices.Concat(original.OOMKills, original.Classification.OOMKills)
				}
				c, err = selectEvidence(in, original, true)
				if err != nil {
					return Output{}, fmt.Errorf("%s classification: %w", original.Target.Name, err)
				}
			}
			finding, err := classifyWorkload(usageIn, c, p)
			if err != nil {
				return Output{}, fmt.Errorf("%s classification: %w", c.Target.Name, err)
			}
			out.Classifications = append(out.Classifications, finding)
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
	settingsStart := max(identity.ReleaseStartedAt, identity.UsageStart)
	switch {
	case identity.Ambiguous:
		addReason(q, ReasonAmbiguousIdentity)
	case !identity.Available || identity.WorkloadUID == "" || identity.Release == "":
		addReason(q, ReasonMissingIdentity)
	case identity.WorkloadUID != c.Target.WorkloadUID || identity.Release != c.Target.Release:
		addReason(q, ReasonAmbiguousIdentity)
	case stale(identity.Timestamp, in, p.Evidence) || identity.Timestamp < settingsStart:
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
	if c.Inventory.CurrentPods != nil {
		// The source may know the whole membership while this resource has
		// samples for only a subset. Explanations report that intersection.
		result.Evidence.Inventory.Observed = min(c.Inventory.Observed, observed)
	}
	var memoryFloor float64
	if !identityBlocked && insufficientRolloutUsage(*q) {
		currentSource := trace.Source
		fallbackUsage, fallbackConfidence, fallbackQuality, fallback, fallbackErr := previousReleaseUsage(in, c, r, p, *q, trace)
		if fallbackErr != nil {
			return ResourceAnalysis{}, fallbackErr
		}
		if fallback != nil {
			// Historical evidence can fill a short history, but cannot justify a
			// limit below a verified peak already reached by this rollout.
			if r == ResourceMemory && p.Memory.SafetyGuards && usage.Available {
				memoryFloor = usage.Value * max(1, headroom)
			}
			if memoryFloor > 0 && usage.Value > fallbackUsage.Value {
				requestTrace.step("current rollout memory peak floor", map[string]float64{"previousPeak": fallbackUsage.Value, "currentPeak": usage.Value})
				trace.Source = currentSource
				fallbackConfidence = min(fallbackConfidence, confidence)
				fallbackUsage = usage
			}
			usage, confidence, *q = fallbackUsage, fallbackConfidence, fallbackQuality
			result.RolloutFallback = fallback
			result.Notices = append(result.Notices, ReasonPreviousReleaseUsage)
		}
	}
	result.Evidence.AggregatedUsage = usage
	usageBlocked := len(q.Reasons) > 0
	oomLimitUnknown := false
	if r == ResourceMemory {
		kills := c.OOMKills
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
		} else if stale(s.value.Timestamp, in, p.Evidence) || s.value.Timestamp < settingsStart {
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
	case stale(c.Inventory.Timestamp, in, p.Evidence) || c.Inventory.Timestamp < settingsStart:
		addReason(q, ReasonStaleInventory)
		inventoryOK = false
	case c.Inventory.Excluded > 0:
		addReason(q, ReasonExcludedContainers)
		inventoryOK = false
	case c.Inventory.Eligible <= 0 || c.Inventory.CurrentPods != nil && len(c.Inventory.CurrentPods) != c.Inventory.Eligible || c.Inventory.Observed != c.Inventory.Eligible || observed != c.Inventory.Eligible:
		addReason(q, ReasonIncompleteInventory)
		inventoryOK = false
	}
	oomCoverageUnknown := r == ResourceMemory && p.Memory.SafetyGuards && c.OOMCoverageIncomplete
	if oomCoverageUnknown {
		addReason(q, ReasonOOMCoverageIncomplete)
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
	// With safety guards, only limits known at event time size the floor. Unknown
	// events remain evidence and still block reductions and new finite limits,
	// but never borrow a later/current allocation or usage as the failed limit.
	sizingKills := result.Evidence.OOMKills
	if r == ResourceMemory && p.Memory.SafetyGuards {
		sizingKills = knownLimitOOMKills(sizingKills)
	}
	if !identityBlocked && requestOK && len(sizingKills) > 0 {
		currentBase := obs.CurrentRequest.Value
		if limitOK && obs.CurrentLimit.Value > 0 {
			currentBase = obs.CurrentLimit.Value
		}
		value, oomErr := oomAdjustment(sizingKills, rawSuggestedRequest, currentBase, p.Memory.OOMKilledCoefficient)
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
		if rawSuggestedRequest < memoryFloor {
			requestTrace.step("current rollout peak minimum", map[string]float64{"before": rawSuggestedRequest, "candidate": memoryFloor})
			rawSuggestedRequest = memoryFloor
		}
	} else {
		confidence = 0 // There is no qualifying usage history to score.
		source := sizingKills[len(sizingKills)-1]
		if p.Memory.SafetyGuards {
			for _, event := range sizingKills {
				if event.MemoryLimitBytes >= source.MemoryLimitBytes {
					source = event
				}
			}
		}
		trace.Source = UsageSource{Release: c.Target.Release, PodUID: source.PodUID, Timestamp: source.Timestamp, Method: "OOM kill"}
		requestTrace.step("OOM sizing without usage history", nil)
	}
	if adjustment != nil {
		result.OOMAdjustment = adjustment
		if p.Memory.SafetyGuards {
			memoryFloor = max(memoryFloor, adjustment.OOMRequestFloorBytes)
		}
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
	memoryHoldReason := Reason("")
	memoryGrowthEvaluated := false
	limitHoldReason := Reason("")
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
		if s.suggested < memoryFloor && (s.suggested < s.current.Value || s.setting == SettingLimits && s.current.Value == 0) {
			settingTrace.stop("retained", ReasonBounds)
			boundsSuppressedAction = true
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
			settingTrace.guard("safe reduction or introduction of limit", inventoryOK && !oomLimitUnknown && !oomCoverageUnknown, nil)
		}
		if (s.suggested < s.current.Value || (s.setting == SettingLimits && s.current.Value == 0)) && (!inventoryOK || oomLimitUnknown || oomCoverageUnknown) {
			for _, reason := range q.Reasons {
				if reason == ReasonUnknownInventory || reason == ReasonStaleInventory || reason == ReasonIncompleteInventory || reason == ReasonExcludedContainers || reason == ReasonOOMLimitUnknown || reason == ReasonOOMCoverageIncomplete {
					settingTrace.Reasons = append(settingTrace.Reasons, reason)
				}
			}
			downsizeSuppressed = downsizeSuppressed || isMaterial(s.current, s.suggested, bounds)
			continue
		}
		// The strict policy also checks demand before introducing a CPU limit.
		// An uncapped container does not need to establish CFS coverage.
		// A held reduction keeps the current limit, which is above the suggested
		// limit and therefore above any request recommended by this pass.
		if r == ResourceCPU && s.setting == SettingLimits && p.CPU.LimitReductionGuard != nil && (s.suggested < s.current.Value || p.CPU.LimitReductionGuard.RequireCompleteCoverage && s.current.Value == 0) && isMaterial(s.current, s.suggested, bounds) {
			if held := cpuLimitReductionHold(in, c, obs, headroom, *p.CPU.LimitReductionGuard, float64(p.Evidence.FreshnessSeconds), s.suggested, settingTrace); len(held) > 0 {
				settingTrace.stop("retained", held...)
				for _, reason := range held {
					result.Notices = appendNotice(result.Notices, reason)
				}
				if limitHoldReason == "" {
					limitHoldReason = held[0]
				}
				continue
			}
		}
		// Opt-in: hold a material memory reduction (request or limit), or the
		// introduction of a finite limit where none was set, while the selected
		// release shows ongoing, mature baseline growth: capping a growing
		// container is as unsafe as shrinking it. Increases of an existing setting
		// are never held. A held reduction keeps its current value, which is above
		// its candidate, and a held introduction keeps the limit unset, so
		// request <= limit is preserved. The detector runs at most once.
		memoryReduction := !s.current.Unset && s.current.Value > 0 && s.suggested < s.current.Value
		memoryLimitIntroduction := s.setting == SettingLimits && (s.current.Unset || s.current.Value == 0) && s.suggested > 0
		if r == ResourceMemory && p.Memory.SafetyGuards && (memoryReduction || memoryLimitIntroduction) && isMaterial(s.current, s.suggested, bounds) {
			if !memoryGrowthEvaluated {
				memoryGrowthEvaluated = true
				var leak *MemoryLeakAnalysis
				memoryHoldReason, leak = memoryGrowthHold(in, c, p, result)
				if p.Memory.LeakDetection != nil {
					// Reused by Analyze for the explicit advisory display.
					result.MemoryLeak = leak
				}
			}
			// Only a hold is traced. Unavailable, immature, stale, unverified, or
			// fallback evidence does not prove that growth is absent, so no passing
			// guard is recorded for it.
			if memoryHoldReason != "" {
				if memoryHoldReason == ReasonMemoryBaselineGrowth {
					settingTrace.guard("no ongoing mature memory growth", false, nil)
				} else {
					settingTrace.guard("continuous runtime known for rising memory baseline", false, nil)
				}
				settingTrace.stop("retained", memoryHoldReason)
				result.Notices = appendUniqueReason(result.Notices, memoryHoldReason)
				continue
			}
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
				if reason == ReasonUnknownInventory || reason == ReasonStaleInventory || reason == ReasonIncompleteInventory || reason == ReasonExcludedContainers || reason == ReasonOOMLimitUnknown || reason == ReasonOOMCoverageIncomplete {
					result.NoActionReason = reason
					break
				}
			}
		}
		if result.NoActionReason == "" && limitHoldReason != "" {
			result.NoActionReason = limitHoldReason
		}
		if result.NoActionReason == "" && memoryHoldReason != "" {
			result.NoActionReason = memoryHoldReason
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

// Allow bounded timestamp jitter without crediting an entire missed scrape or
// extending the freshness, history, or observation-count requirements.
const coverageGapTolerance = 1.25

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
		last := timestamps[len(timestamps)-1]
		runtimeStart, current := c.Inventory.CurrentPods[s.PodUID]
		if (c.Inventory.CurrentPods == nil || s.PodUID != "" && current && last >= runtimeStart) && !stale(last, in, p.Evidence) {
			pods[pod] = true
		}
		releaseTimes = append(releaseTimes, timestamps...)
		n := len(timestamps)
		q.SampleCount += n

		first := timestamps[0]
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
			seriesCovered += math.Min(gap, cadence*coverageGapTolerance)
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
		covered += math.Min(gap, cadence*coverageGapTolerance)
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
func selectReleaseSegment(in Input, c ContainerObservation, reliability bool) (ContainerObservation, int64) {
	if c.Identity.RolloutBoundaryVerified && c.Identity.ReleaseStartedAt > 0 {
		// Other releases can still be serving Pods after the verified activation.
		return c, c.Identity.ReleaseStartedAt
	}
	cutoff := in.WindowStart - 1
	var currentSince int64
	for uid, started := range c.Inventory.CurrentPods {
		if uid != "" && c.Inventory.Available && started > 0 && started <= c.Inventory.Timestamp && (currentSince == 0 || started < currentSince) {
			currentSince = started
		}
	}
	rows := [][]Series{c.CPU.Series, c.Memory.Series}
	if reliability && c.Classification != nil {
		throttling := c.Classification.Throttling
		rows = append(rows, throttling.Periods, throttling.ThrottledPeriods, throttling.Seconds)
	}
	for _, series := range rows {
		for _, s := range series {
			if s.WorkloadUID != c.Target.WorkloadUID || s.Release == "" || s.Release == c.Target.Release {
				continue
			}
			for _, v := range s.Samples {
				// A known current Pod was already serving this release. Concurrent
				// older replicas are ordinary overlap, not an intervening activation.
				if v.Timestamp <= in.EvaluationTime && v.Timestamp > cutoff && (currentSince == 0 || v.Timestamp < currentSince || v.Timestamp > c.Inventory.Timestamp) {
					cutoff = v.Timestamp
				}
			}
		}
	}
	boundary := int64(0)
	for _, series := range rows {
		for _, s := range series {
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
		c.Identity.RolloutBoundaryVerified = true
		c.Identity.ReleaseStartedAt = boundary
		c.Identity.ReleaseStartInferred = true
	}
	// First collection cannot exclude a known current Pod's earlier event.
	// Only a recorded activation or an intervening revision fences that event.
	if c.Identity.ReleaseStartInferred && !c.Identity.RolloutBoundaryVerified {
		return c, cutoff + 1
	}
	return c, c.Identity.ReleaseStartedAt
}
