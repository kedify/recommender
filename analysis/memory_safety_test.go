// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func safetyPolicy(p Policy) Policy {
	p.Memory.SafetyGuards = true
	return p
}

func advisoryLeakPolicy(p Policy) Policy {
	p.Memory.LeakDetection = &MemoryLeakPolicy{}
	return p
}

func growthInput(hours int64, request, limit float64) Input {
	in := leakFixture(hours, func(h float64) float64 { return 100 + 12*h })
	in.Containers[0].Memory.CurrentRequest.Value = request
	in.Containers[0].Memory.CurrentLimit.Value = limit
	return in
}

func withOOMKills(in Input, kills ...OOMKill) Input {
	in.Containers = append([]ContainerObservation(nil), in.Containers...)
	in.Containers[0].OOMKills = kills
	return in
}

func settingTraceFor(t *testing.T, r ResourceAnalysis, setting Setting) SettingTrace {
	t.Helper()
	if r.DecisionTrace != nil {
		for _, st := range r.DecisionTrace.Settings {
			if st.Setting == setting {
				return st
			}
		}
	}
	t.Fatalf("missing %s decision trace: %+v", setting, r.DecisionTrace)
	return SettingTrace{}
}

func reasonsHave(reasons []Reason, reason Reason) bool {
	for _, r := range reasons {
		if r == reason {
			return true
		}
	}
	return false
}

func recommendationFor(r ResourceAnalysis, setting Setting) (Recommendation, bool) {
	for _, rec := range r.Recommendations {
		if rec.Setting == setting {
			return rec, true
		}
	}
	return Recommendation{}, false
}

func TestMemorySafetyGuardsAreOptIn(t *testing.T) {
	encoded, err := json.Marshal(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "safetyGuards") {
		t.Fatalf("default policy JSON changed: %s", encoded)
	}
	var decoded Policy
	if err = json.Unmarshal([]byte(`{"memory":{"strategy":"max"}}`), &decoded); err != nil || decoded.Memory.SafetyGuards {
		t.Fatalf("old policies must leave safety guards off: %+v, %v", decoded.Memory, err)
	}
	legacyVersion, err := PolicyVersion(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	guardedVersion, err := PolicyVersion(safetyPolicy(DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if legacyVersion == guardedVersion {
		t.Fatal("safety guards must be part of the policy version")
	}
	guardedJSON, err := json.Marshal(safetyPolicy(DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guardedJSON), `"safetyGuards":true`) {
		t.Fatalf("enabled safety guards are not explicit: %s", guardedJSON)
	}

	// Without OOM evidence or mature growth, opting in leaves sizing unchanged.
	in := fixture(600, 60)
	legacy := run(t, in, shortPolicy())
	guarded := run(t, in, safetyPolicy(shortPolicy()))
	if len(guarded.Results[0].Recommendations) == 0 {
		t.Fatal("expected an unguarded memory reduction")
	}
	for i := range legacy.Results {
		want, got := legacy.Results[i], guarded.Results[i]
		if !reflect.DeepEqual(got.Recommendations, want.Recommendations) || got.NoActionReason != want.NoActionReason || !reflect.DeepEqual(got.Notices, want.Notices) || !reflect.DeepEqual(got.DataQuality, want.DataQuality) || got.MemoryLeak != nil {
			t.Fatalf("safety guards changed ordinary sizing: legacy=%+v guarded=%+v", want, got)
		}
	}
}

func TestMemorySafetyOOMFloorUsesOnlyKnownEventLimits(t *testing.T) {
	known := oomKill("known", epoch+60000, 64*mib)
	unknown := oomKill("unknown", epoch+120000, 0)
	base := fixture(600, 60)
	base.Containers[0].Memory.CurrentRequest.Value = 64 * mib
	// Raised after both kills: never the limit in effect when the unknown event failed.
	base.Containers[0].Memory.CurrentLimit.Value = 128 * mib
	in := withOOMKills(base, unknown, known, known) // Repeated observation of one event.
	p := safetyPolicy(shortPolicy())

	legacy := run(t, in, shortPolicy()).Results[0]
	if legacy.OOMAdjustment == nil || !legacy.OOMAdjustment.UsedCurrentFallback || legacy.OOMAdjustment.OOMRequestFloorBytes != 192*mib {
		t.Fatalf("legacy timestamp-only fallback changed: %+v", legacy.OOMAdjustment)
	}
	out := run(t, in, p)
	r := out.Results[0]
	if r.OOMAdjustment == nil || r.OOMAdjustment.OOMRequestFloorBytes != 96*mib || r.OOMAdjustment.UsedCurrentFallback || r.OOMAdjustment.UsedUsageFallback {
		t.Fatalf("OOM floor must use only the known 64 MiB event limit: %+v", r.OOMAdjustment)
	}
	if !reflect.DeepEqual(r.Evidence.OOMKills, []OOMKill{known, unknown}) || !reflect.DeepEqual(r.Notices, []Reason{ReasonOOMKillDetected}) {
		t.Fatalf("OOM evidence was not preserved and deduplicated: %+v", r)
	}
	if r.DataQuality.Status != DataQualityPartial || !has(r.DataQuality, ReasonOOMLimitUnknown) {
		t.Fatalf("unknown event limit was hidden: %+v", r.DataQuality)
	}
	request, okRequest := recommendationFor(r, SettingRequests)
	limit, okLimit := recommendationFor(r, SettingLimits)
	if !okRequest || !okLimit || request.SuggestedValue != 96*mib || limit.SuggestedValue != 288*mib || request.SuggestedValue > limit.SuggestedValue {
		t.Fatalf("known valid increases were not preserved: %+v", r.Recommendations)
	}
	if !reflect.DeepEqual(run(t, in, p), out) {
		t.Fatal("rerun changed guarded output")
	}
	more := withOOMKills(base, oomKill("unknown-2", epoch+180000, 0), known, unknown)
	again := run(t, more, p).Results[0]
	if !reflect.DeepEqual(again.Recommendations, r.Recommendations) || !reflect.DeepEqual(again.OOMAdjustment, r.OOMAdjustment) {
		t.Fatalf("order or additional unknown events changed the 96 MiB floor: %+v", again)
	}
}

func TestMemorySafetyUnknownOOMStillBlocksReductionAndNewLimit(t *testing.T) {
	known := oomKill("known", epoch+60000, 64*mib)
	unknown := oomKill("unknown", epoch+120000, 0)
	p := safetyPolicy(shortPolicy())

	// Fixture current settings are 256 MiB request and 512 MiB limit.
	in := withOOMKills(fixture(600, 60), known, unknown)
	legacy := run(t, in, shortPolicy()).Results[0]
	if legacy.OOMAdjustment == nil || legacy.OOMAdjustment.OOMRequestFloorBytes != 768*mib {
		t.Fatalf("legacy current-limit fallback changed: %+v", legacy.OOMAdjustment)
	}
	r := run(t, in, p).Results[0]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonOOMLimitUnknown || r.OOMAdjustment == nil || r.OOMAdjustment.OOMRequestFloorBytes != 96*mib {
		t.Fatalf("unknown event must suppress reductions without using the current limit: %+v", r)
	}
	for _, setting := range []Setting{SettingRequests, SettingLimits} {
		if !reasonsHave(settingTraceFor(t, r, setting).Reasons, ReasonOOMLimitUnknown) {
			t.Fatalf("%s trace omits unknown OOM limit: %+v", setting, r.DecisionTrace)
		}
	}

	unset := fixture(600, 60)
	unset.Containers[0].Memory.CurrentRequest.Value = 64 * mib
	unset.Containers[0].Memory.CurrentLimit = Signal{Available: true, Unset: true, Timestamp: unset.EvaluationTime}
	r = run(t, withOOMKills(unset, known, unknown), p).Results[0]
	request, ok := recommendationFor(r, SettingRequests)
	if _, created := recommendationFor(r, SettingLimits); !ok || request.SuggestedValue != 96*mib || created || !reasonsHave(settingTraceFor(t, r, SettingLimits).Reasons, ReasonOOMLimitUnknown) {
		t.Fatalf("unknown event must block creating a finite limit but keep the known increase: %+v", r)
	}
}

func TestMemorySafetyOOMWithoutUsage(t *testing.T) {
	known := oomKill("known", epoch+60000, 64*mib)
	unknown := oomKill("unknown", epoch+120000, 0)
	base := fixture(600, 60)
	base.Containers[0].Memory.Series = nil
	base.Containers[0].Memory.CurrentRequest.Value = 64 * mib
	base.Containers[0].Memory.CurrentLimit.Value = 128 * mib
	p := safetyPolicy(shortPolicy())

	r := run(t, withOOMKills(base, known, unknown), p).Results[0]
	if r.OOMAdjustment == nil || r.OOMAdjustment.OOMRequestFloorBytes != 96*mib || r.OOMAdjustment.BaselineRequestBytes != 0 || r.OOMAdjustment.UsedCurrentFallback || r.OOMAdjustment.UsedUsageFallback {
		t.Fatalf("known OOM must size without usage or fallbacks: %+v", r.OOMAdjustment)
	}
	request, okRequest := recommendationFor(r, SettingRequests)
	limit, okLimit := recommendationFor(r, SettingLimits)
	if !okRequest || !okLimit || request.SuggestedValue != 96*mib || limit.SuggestedValue != 288*mib || request.Confidence != 0 {
		t.Fatalf("unexpected OOM-only sizing: %+v", r.Recommendations)
	}
	if r.DecisionTrace.Source.Timestamp != known.Timestamp || !has(r.DataQuality, ReasonMissingUsage) || !has(r.DataQuality, ReasonOOMLimitUnknown) {
		t.Fatalf("OOM-only source must be the known event: %+v %+v", r.DecisionTrace.Source, r.DataQuality)
	}

	only := withOOMKills(base, unknown)
	legacy := run(t, only, shortPolicy()).Results[0]
	if legacy.OOMAdjustment == nil || !legacy.OOMAdjustment.UsedCurrentFallback || len(legacy.Recommendations) == 0 {
		t.Fatalf("legacy unknown-only behavior changed: %+v", legacy)
	}
	r = run(t, only, p).Results[0]
	if r.DataQuality.Status != DataQualityUnavailable || r.NoActionReason != ReasonMissingUsage || !has(r.DataQuality, ReasonOOMLimitUnknown) || r.OOMAdjustment != nil || len(r.Recommendations) != 0 {
		t.Fatalf("unknown-only OOM without usage must not size: %+v", r)
	}
	if !reflect.DeepEqual(r.Evidence.OOMKills, []OOMKill{unknown}) || !reflect.DeepEqual(r.Notices, []Reason{ReasonOOMKillDetected}) {
		t.Fatalf("unknown OOM evidence was not retained: %+v", r)
	}
	for _, setting := range []Setting{SettingRequests, SettingLimits} {
		st := settingTraceFor(t, r, setting)
		if st.Disposition != "unavailable" || !reasonsHave(st.Reasons, ReasonMissingUsage) || !reasonsHave(st.Reasons, ReasonOOMLimitUnknown) {
			t.Fatalf("%s trace is imprecise: %+v", setting, st)
		}
	}
}

func TestMemorySafetyHoldsReductionsDuringMatureGrowth(t *testing.T) {
	in := growthInput(6, 512*mib, 1024*mib)
	legacy := run(t, in, DefaultPolicy())
	if len(legacy.Results[0].Recommendations) != 2 {
		t.Fatalf("expected legacy reductions: %+v", legacy.Results[0])
	}
	out := run(t, in, safetyPolicy(DefaultPolicy()))
	r := out.Results[0]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonMemoryBaselineGrowth || !reflect.DeepEqual(r.Notices, []Reason{ReasonMemoryBaselineGrowth}) || r.MemoryLeak != nil {
		t.Fatalf("mature growth must hold reductions privately: %+v", r)
	}
	for _, setting := range []Setting{SettingRequests, SettingLimits} {
		if st := settingTraceFor(t, r, setting); st.Disposition != "retained" || !reasonsHave(st.Reasons, ReasonMemoryBaselineGrowth) {
			t.Fatalf("%s hold missing from trace: %+v", setting, st)
		}
	}
	if !reflect.DeepEqual(out.Results[1], legacy.Results[1]) {
		t.Fatal("memory safety changed CPU analysis")
	}

	// Explicit detection stays advisory on its own and is reused, not recomputed differently.
	explicit := run(t, in, advisoryLeakPolicy(DefaultPolicy())).Results[0]
	if explicit.MemoryLeak == nil || explicit.MemoryLeak.Status != MemoryLeakPotential || len(explicit.Recommendations) != 2 {
		t.Fatalf("explicit leak detection must remain advisory: %+v", explicit)
	}
	both := run(t, in, safetyPolicy(advisoryLeakPolicy(DefaultPolicy()))).Results[0]
	if !reflect.DeepEqual(both.MemoryLeak, explicit.MemoryLeak) || len(both.Recommendations) != 0 || !reflect.DeepEqual(both.Notices, []Reason{ReasonMemoryBaselineGrowth, ReasonPotentialMemoryLeak}) {
		t.Fatalf("guarded explicit analysis diverged: %+v", both)
	}
}

func TestMemorySafetyPreservesIncreasesAndRequestLimitDependency(t *testing.T) {
	p := safetyPolicy(DefaultPolicy())
	r := run(t, growthInput(6, 64*mib, 128*mib), p).Results[0]
	request, okRequest := recommendationFor(r, SettingRequests)
	limit, okLimit := recommendationFor(r, SettingLimits)
	if !okRequest || !okLimit || request.SuggestedValue <= 64*mib || limit.SuggestedValue <= 128*mib || request.SuggestedValue > limit.SuggestedValue || reasonsHave(r.Notices, ReasonMemoryBaselineGrowth) {
		t.Fatalf("growth must not hold increases: %+v", r)
	}

	// The request increases while the limit reduction is held at its current value.
	r = run(t, growthInput(6, 128*mib, 2048*mib), p).Results[0]
	request, okRequest = recommendationFor(r, SettingRequests)
	_, okLimit = recommendationFor(r, SettingLimits)
	if !okRequest || okLimit || request.SuggestedValue <= 128*mib || request.SuggestedValue > 2048*mib || !reasonsHave(settingTraceFor(t, r, SettingLimits).Reasons, ReasonMemoryBaselineGrowth) || !reflect.DeepEqual(r.Notices, []Reason{ReasonMemoryBaselineGrowth}) {
		t.Fatalf("held limit must keep covering the increased request: %+v", r)
	}

	// The request reduction is held, so the limit increase must still cover it.
	r = run(t, growthInput(6, 512*mib, 512*mib), p).Results[0]
	_, okRequest = recommendationFor(r, SettingRequests)
	limit, okLimit = recommendationFor(r, SettingLimits)
	if okRequest || !okLimit || limit.SuggestedValue < 512*mib || !reasonsHave(settingTraceFor(t, r, SettingRequests).Reasons, ReasonMemoryBaselineGrowth) {
		t.Fatalf("limit increase must cover the retained request: %+v", r)
	}
}

func unsetLimitGrowthInput(request float64) Input {
	in := growthInput(6, request, 0)
	in.Containers[0].Memory.CurrentLimit = Signal{Available: true, Unset: true, Timestamp: in.EvaluationTime}
	return in
}

func TestMemorySafetyHoldsNewFiniteLimitDuringMatureGrowth(t *testing.T) {
	p := safetyPolicy(DefaultPolicy())

	// The request increase proceeds unchanged; capping the growing container waits.
	in := unsetLimitGrowthInput(64 * mib)
	legacy := run(t, in, DefaultPolicy()).Results[0]
	legacyRequest, okLegacyRequest := recommendationFor(legacy, SettingRequests)
	if _, created := recommendationFor(legacy, SettingLimits); !okLegacyRequest || !created {
		t.Fatalf("expected a legacy request increase and new limit: %+v", legacy)
	}
	r := run(t, in, p).Results[0]
	request, okRequest := recommendationFor(r, SettingRequests)
	_, created := recommendationFor(r, SettingLimits)
	st := settingTraceFor(t, r, SettingLimits)
	if !okRequest || request.SuggestedValue != legacyRequest.SuggestedValue || request.SuggestedValue <= 64*mib || created || st.Disposition != "retained" || !reasonsHave(st.Reasons, ReasonMemoryBaselineGrowth) || !reflect.DeepEqual(r.Notices, []Reason{ReasonMemoryBaselineGrowth}) {
		t.Fatalf("growth must hold a new finite limit but not the request increase: %+v", r)
	}
	trace, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trace), "no ongoing mature memory growth") {
		t.Fatalf("held limit introduction must trace the failed growth guard: %s", trace)
	}

	// A held request reduction and a held introduction leave no action.
	r = run(t, unsetLimitGrowthInput(512*mib), p).Results[0]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonMemoryBaselineGrowth {
		t.Fatalf("growth must hold both the reduction and the new limit: %+v", r)
	}

	// Without growth the limit is introduced exactly as before.
	flat := leakFixture(6, func(float64) float64 { return 100 })
	flat.Containers[0].Memory.CurrentRequest.Value = 64 * mib
	flat.Containers[0].Memory.CurrentLimit = Signal{Available: true, Unset: true, Timestamp: flat.EvaluationTime}
	r = assertGrowthNotHeld(t, flat, DefaultPolicy())
	if _, created := recommendationFor(r, SettingLimits); !created {
		t.Fatalf("a new limit without growth must not be held: %+v", r)
	}
}

func thinMemoryBuckets(in Input) Input {
	s := &in.Containers[0].Memory.Series[0]
	kept := make([]Sample, 0, len(s.Samples))
	for _, sample := range s.Samples {
		offset := sample.Timestamp - epoch
		// Leave four samples in the leak buckets starting 1.5h and 2.5h in.
		thinned := (offset >= 5400000 && offset < 7200000) || (offset >= 9000000 && offset < 10800000)
		if thinned && offset%1800000 >= 240000 {
			continue
		}
		kept = append(kept, sample)
	}
	s.Samples = kept
	return in
}

func assertGrowthNotHeld(t *testing.T, in Input, p Policy) ResourceAnalysis {
	t.Helper()
	legacy := run(t, in, p).Results[0]
	r := run(t, in, safetyPolicy(p)).Results[0]
	if len(legacy.Recommendations) == 0 || !reflect.DeepEqual(r.Recommendations, legacy.Recommendations) || reasonsHave(r.Notices, ReasonMemoryBaselineGrowth) {
		t.Fatalf("growth guard held without mature fresh evidence: legacy=%+v guarded=%+v", legacy, r)
	}
	trace, err := json.Marshal(r.DecisionTrace)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(trace), "mature memory growth") {
		t.Fatalf("unproven growth evidence was traced as an affirmative guard: %s", trace)
	}
	return r
}

func TestMemorySafetyDoesNotHoldEarlySparseWarmupOrInferredGrowth(t *testing.T) {
	t.Run("early advisory finding", func(t *testing.T) {
		r := assertGrowthNotHeld(t, growthInput(3, 512*mib, 1024*mib), advisoryLeakPolicy(DefaultPolicy()))
		if r.MemoryLeak == nil || r.MemoryLeak.Status != MemoryLeakPotential {
			t.Fatalf("expected an advisory-only early finding: %+v", r.MemoryLeak)
		}
	})
	t.Run("allocated but unusable buckets", func(t *testing.T) {
		p := advisoryLeakPolicy(DefaultPolicy())
		p.Evidence.MinimumCoverage = .7
		r := assertGrowthNotHeld(t, thinMemoryBuckets(growthInput(4, 512*mib, 1024*mib)), p)
		leak := r.MemoryLeak
		if leak == nil || leak.Status != MemoryLeakPotential || len(leak.Episodes) != 1 || leak.Episodes[0].BucketCount != 7 || leak.Episodes[0].UsableHistoryHours != 2.5 {
			t.Fatalf("expected seven allocated but five usable buckets: %+v", leak)
		}
	})
	t.Run("warmup spike", func(t *testing.T) {
		in := leakFixture(6, func(h float64) float64 {
			if h < .4 {
				return 600
			}
			return 200
		})
		in.Containers[0].Memory.CurrentRequest.Value = 1024 * mib
		in.Containers[0].Memory.CurrentLimit.Value = 2048 * mib
		assertGrowthNotHeld(t, in, DefaultPolicy())
	})
	t.Run("inferred release boundary", func(t *testing.T) {
		in := growthInput(6, 512*mib, 1024*mib)
		in.Containers[0].Identity.ReleaseStartedAt = 0
		if r := assertGrowthNotHeld(t, in, DefaultPolicy()); !has(r.DataQuality, ReasonInferredReleaseStart) {
			t.Fatalf("expected an inferred boundary: %+v", r.DataQuality)
		}
	})
}
