// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0

package analysis

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestCurrentPeakFloorsPreviousReleaseSizing(t *testing.T) {
	in := fixture(300, 60)
	in.WindowStart -= 3 * 3600_000
	c := &in.Containers[0]
	past := previousFixture("previous", epoch-60_000, 7200, 60)
	for i := range past.Memory[0].Samples {
		past.Memory[0].Samples[i].Value = 100 * mib
	}
	c.PreviousReleases = []PreviousRelease{past}
	for i := range c.Memory.Series[0].Samples {
		c.Memory.Series[0].Samples[i].Value = 200 * mib
	}
	p := safetyPolicy(DefaultPolicy())
	p.Memory.HeadroomCoefficient, p.Memory.LimitsToRequestsRatio = 1.15, 1
	r := run(t, in, p).Results[0]
	if r.RolloutFallback == nil || r.DecisionTrace.Source.Release != "A" || r.Evidence.AggregatedUsage.Value != 200*mib ||
		len(r.Recommendations) != 2 || r.Recommendations[1].SuggestedValue < 229*mib || r.Recommendations[1].Confidence >= 95 {
		t.Fatalf("discarded current usage or borrowed historical confidence: %+v", r)
	}
	lowHeadroom := p
	lowHeadroom.Memory.HeadroomCoefficient = .5
	if r := run(t, in, lowHeadroom).Results[0]; len(r.Recommendations) != 2 || r.Recommendations[1].SuggestedValue != 200*mib {
		t.Fatalf("low headroom cut below the current observed peak: %+v", r)
	}
	capped := p
	capped.Memory.Bounds.Maximum = 128 * mib
	if r := run(t, in, capped).Results[0]; len(r.Recommendations) != 0 {
		t.Fatalf("a policy maximum below current usage authorized a reduction: %+v", r)
	}
	request, limit := c.Memory.CurrentRequest, c.Memory.CurrentLimit
	c.Memory.CurrentRequest.Value, c.Memory.CurrentLimit.Value = 64*mib, 0
	if r := run(t, in, capped).Results[0]; len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
		t.Fatalf("numeric zero introduced a cap below current usage: %+v", r)
	}
	c.Memory.CurrentRequest, c.Memory.CurrentLimit = request, limit
	c.OOMKills = []OOMKill{oomKill("failed", epoch+60_000, 512*mib)}
	r = run(t, in, p).Results[0]
	if r.Recommendations[1].SuggestedValue != 768*mib {
		t.Fatalf("lost current OOM floor: %+v", r)
	}
}

func TestOOMSelectsCurrentActivationForSizingAndClassification(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch + 300_000}
	c.Identity.ReleaseStartInferred = true
	c.Identity.ReleaseStartedAt = epoch + 300_000
	c.OOMKills = []OOMKill{oomKill("early", epoch+60_000, 512*mib)}
	c.Classification = &ClassificationObservation{}
	p := safetyPolicy(shortPolicy())
	p.Classification = &ClassificationPolicy{}
	for _, tc := range []struct {
		name     string
		boundary bool
		middle   bool
		want     int
	}{
		{"first inventory", false, false, 1}, {"verified activation", true, false, 0}, {"intervening CFS", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.Identity.RolloutBoundaryVerified = tc.boundary
			if tc.middle {
				c.Classification.Throttling.Periods = []Series{guardCounter("other", "B", epoch+120_000, []float64{1, 2})}
			}
			out := run(t, in, p)
			r := out.Results[0]
			if len(r.Evidence.OOMKills) != tc.want || len(finding(out.Classifications[0], FeatureOOMKilled).OOMKills) != tc.want {
				t.Fatalf("mismatched activation: %+v", out)
			}
		})
	}
}

func TestOOMCoverageIsResourceLocalAndPositiveEventsAgree(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	p := safetyPolicy(shortPolicy())
	c.OOMCoverageIncomplete = true
	out := run(t, in, p)
	if len(out.Results[0].Recommendations) != 0 || !has(out.Results[0].DataQuality, ReasonOOMCoverageIncomplete) ||
		len(out.Results[1].Recommendations) == 0 {
		t.Fatalf("unreliable collection affected wrong decisions: %+v", out.Results)
	}
	c.OOMCoverageIncomplete = false
	early := oomKill("strong", epoch+60_000, 512*mib)
	early.PodUID = "old"
	later := oomKill("weak", epoch+120_000, 64*mib)
	c.Memory.Series = nil
	c.OOMKills = []OOMKill{later, early}
	snapshot := early
	snapshot.MemoryLimitBytes = 0
	c.Classification = &ClassificationObservation{OOMKills: []OOMKill{snapshot}}
	r := run(t, in, p).Results[0]
	if len(r.Evidence.OOMKills) != 2 || r.OOMAdjustment.OOMRequestFloorBytes != 768*mib ||
		r.DecisionTrace.Source.Timestamp != early.Timestamp || r.DecisionTrace.Source.PodUID != early.PodUID {
		t.Fatalf("wrong floor provenance: %+v", r)
	}
	c.Memory.Series = fixture(600, 60).Containers[0].Memory.Series
	c.Memory.CurrentLimit.Value = 1024 * mib
	p.Memory.Bounds.Maximum = 384 * mib
	r = run(t, in, p).Results[0]
	if _, issued := recommendationFor(r, SettingLimits); issued {
		t.Fatalf("maximum cut below failed limit: %+v", r)
	}
}

func TestRetiredReplicaCannotSupplyCoverageOrOngoingGrowth(t *testing.T) {
	in := growthInput(6, 512*mib, 1024*mib)
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"replacement": epoch}
	p := safetyPolicy(DefaultPolicy())
	r := run(t, in, p).Results[0]
	if len(r.Recommendations) != 0 || r.Evidence.Inventory.Observed != 0 || !has(r.DataQuality, ReasonIncompleteInventory) {
		t.Fatalf("retired replica substituted for live: %+v", r)
	}
	survivor := c.Memory.Series[0]
	survivor.ID, survivor.PodUID = "flat", "replacement"
	survivor.Samples = slices.Clone(survivor.Samples)
	for i := range survivor.Samples {
		survivor.Samples[i].Value = 100 * mib
	}
	c.Memory.Series = append(c.Memory.Series, survivor)
	r = run(t, in, p).Results[0]
	if len(r.Recommendations) != 2 || r.Evidence.AggregatedUsage.Value <= 100*mib {
		t.Fatalf("retired trend vetoed current advice or discarded historical peak: %+v", r)
	}
}

func TestMemoryGrowthRequiresContinuousRuntime(t *testing.T) {
	in := growthInput(6, 512*mib, 1024*mib)
	c := &in.Containers[0]
	p := safetyPolicy(DefaultPolicy())
	for i := range c.Memory.Series[0].Samples {
		c.Memory.Series[0].Samples[i].Value = float64(100+24*(i/60)) * mib
	}
	for _, tc := range []struct {
		start int64
		hold  bool
	}{{epoch, true}, {epoch + 5*3600_000, false}, {0, false}} {
		c.Inventory.CurrentPods = map[string]int64{"pod-1": tc.start}
		r := run(t, in, p).Results[0]
		if slices.Contains(r.Notices, ReasonMemoryBaselineGrowth) != tc.hold {
			t.Fatalf("start=%d incorrect growth decision: %+v", tc.start, r)
		}
	}
}

func TestRecurringDemandOutlivesCounterCollectionAndProtectsNewCaps(t *testing.T) {
	in := fixture(7200, 60)
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch}
	s := &c.CPU.Series[0]
	s.ID, s.Kind = "runtime", SampleCPUCounterSeconds
	setUsage := func(bursty bool) {
		total := 0.0
		for i := range s.Samples {
			rate := 20.0
			if bursty && (i == 10 || i == 30 || i == 50) {
				rate = 800
			}
			total += rate / 1000 * 60
			s.Samples[i].Value = total
		}
	}
	setUsage(true)
	mk := func(step float64) Series {
		row := guardCounter(s.ID, "A", in.EvaluationTime-5*60_000, guardRamp(6, step))
		row.PodUID = s.PodUID
		return row
	}
	c.Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{SourceComplete: true, Periods: []Series{mk(100)}, ThrottledPeriods: []Series{mk(0)}, Seconds: []Series{mk(0)}}}
	p := guardStrictPolicy()
	p.CPU.HeadroomCoefficient, p.CPU.Percentile, p.CPU.LimitsToRequestsRatio = 1, 66, 5
	// Source-specific usage and quota metric IDs both identify the same Pod
	// with a verified runtime start. Their IDs need not match across metrics.
	s.ID = "cpu-usage"
	current := c.CPU.CurrentLimit
	for _, limit := range []Signal{current, {Available: true, Timestamp: in.EvaluationTime}, {Available: true, Unset: true, Timestamp: in.EvaluationTime}} {
		c.CPU.CurrentLimit = limit
		if limit.Value == 0 {
			c.Classification = nil
		}
		r := run(t, in, p).Results[1]
		if _, ok := guardRecommendation(r, SettingLimits); ok || !slices.Contains(r.Notices, ReasonCPULimitBelowDemand) {
			t.Fatalf("limit=%+v: %+v", limit, r)
		}
	}
	setUsage(false)
	r := run(t, in, p).Results[1]
	if limit, ok := guardRecommendation(r, SettingLimits); !ok || limit.SuggestedValue < 99.99 || limit.SuggestedValue > 100.01 {
		t.Fatalf("healthy introduction incorrectly required CFS: %+v", r)
	}
	c.Inventory.CurrentPods["pod-1"] = 0
	r = run(t, in, p).Results[1]
	if _, ok := guardRecommendation(r, SettingLimits); ok || !slices.Contains(r.Notices, ReasonCPULimitEvidenceIncomplete) {
		t.Fatalf("unknown runtime certified the first CPU cap: %+v", r)
	}
}

func TestConcurrentPreviousReleaseOOMCannotFenceCurrentUsage(t *testing.T) {
	in := fixture(7200, 60)
	p := safetyPolicy(DefaultPolicy())
	before := run(t, in, p)
	old := oomKill("old", in.EvaluationTime-60_000, 512*mib)
	old.PodUID, old.Release = "old-pod", "old"
	in.Containers[0].OOMKills = []OOMKill{old}
	after := run(t, in, p)
	if !slices.Equal(before.Results[0].Recommendations, after.Results[0].Recommendations) ||
		before.Results[0].Evidence.Identity.ReleaseStartedAt != after.Results[0].Evidence.Identity.ReleaseStartedAt {
		t.Fatal("historical event moved an active rollout's boundary")
	}
}

func TestRecordedEmptyCurrentMembershipCannotBecomeLegacyCounts(t *testing.T) {
	in := fixture(600, 60)
	in.Containers[0].Inventory.CurrentPods = map[string]int64{}
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var saved Input
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	r := run(t, saved, safetyPolicy(shortPolicy())).Results[0]
	if len(r.Recommendations) != 0 || r.Evidence.Inventory.Observed != 0 || !has(r.DataQuality, ReasonIncompleteInventory) {
		t.Fatalf("saved membership lost its exact-set semantics: %+v", r)
	}
}

func TestVerifiedCurrentQuotaIsIndependentOfRetiredAdvisoryPressure(t *testing.T) {
	in := guardCoverageInput(make([]float64, 11))
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch + 7*60_000}
	o := guardCFS(&in)
	o.CoverageAt = in.EvaluationTime
	for _, rows := range [][]Series{o.Periods, o.ThrottledPeriods, o.Seconds} {
		rows[0].Samples = rows[0].Samples[7:]
	}
	old := guardFamily("retired", "pod-1", guardRamp(7, 5))
	old.CPUGuardAdvisoryOnly = true
	o.ThrottledPeriods = append(o.ThrottledPeriods, old)
	result := run(t, in, guardStrictPolicy()).Results[1]
	if rec, ok := guardRecommendation(result, SettingLimits); !ok || rec.SuggestedValue != 150 {
		t.Fatalf("retired quota blocked a verified current reduction: %+v", result)
	}
	o.SourceComplete = false
	result = run(t, in, guardStrictPolicy()).Results[1]
	if _, ok := guardRecommendation(result, SettingLimits); ok || !slices.Contains(result.Notices, ReasonCPULimitEvidenceIncomplete) {
		t.Fatalf("unverified quota authorized a reduction: %+v", result)
	}
}

func TestVerifiedRolloutBoundarySurvivesOverlappingCounters(t *testing.T) {
	in := fixture(3600, 60)
	c := &in.Containers[0]
	c.Identity.ReleaseStartedAt = epoch + 5*60000
	c.Identity.ReleaseStartInferred, c.Identity.RolloutBoundaryVerified = true, true
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch + 5*60000}
	c.OOMKills = []OOMKill{oomKill("current", epoch+6*60000, 512*mib)}
	c.Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Periods: []Series{guardCounter("previous", "B", epoch+10*60000, []float64{0, 3})}}}
	p := safetyPolicy(shortPolicy())
	p.Classification = &ClassificationPolicy{}
	o := run(t, in, p)
	if r := o.Results[0]; r.OOMAdjustment == nil || r.OOMAdjustment.OOMRequestFloorBytes != 768*mib || len(finding(o.Classifications[0], FeatureOOMKilled).OOMKills) != 1 {
		t.Fatalf("concurrent release erased a current OOM: %+v", r)
	}
}

func TestLegacyClassificationCanPrecedeFirstUsage(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	c.Identity.ReleaseStartedAt = 0
	in.WindowStart -= 60000
	c.Classification = &ClassificationObservation{OOMKills: []OOMKill{oomKill("cold", epoch-30000, 512*mib)}}
	p := shortPolicy()
	p.Classification = &ClassificationPolicy{}
	o := run(t, in, p)
	if len(finding(o.Classifications[0], FeatureOOMKilled).OOMKills) != 1 || len(o.Results[0].Evidence.OOMKills) != 0 {
		t.Fatal("legacy classification lost its independently attributed early OOM")
	}
}

func TestQuotaResizeRetainsWholeRuntimeClassification(t *testing.T) {
	in := guardCoverageInput(make([]float64, 11))
	c := &in.Containers[0]
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch}
	cf := guardCFS(&in)
	for i := range cf.ThrottledPeriods[0].Samples {
		cf.ThrottledPeriods[0].Samples[i].Value = float64(min(i, 3))
	}
	p := guardStrictPolicy()
	p.Classification = &ClassificationPolicy{}
	for _, tc := range []struct {
		minutes      int64
		currentProof bool
	}{{8, true}, {9, false}} {
		for _, family := range [][]Series{cf.Seconds, cf.ThrottledPeriods, cf.Periods} {
			family[0].CPUGuardStart = epoch + tc.minutes*60000
		}
		out := run(t, in, p)
		_, issued := guardRecommendation(out.Results[1], SettingLimits)
		f := finding(out.Classifications[0], FeatureCPUThrottled)
		if issued != tc.currentProof || f.Status != ClassificationDetected || len(f.Throttling) != 1 || f.Throttling[0].ThrottledPeriods == nil || *f.Throttling[0].ThrottledPeriods != 3 {
			t.Fatalf("resize at minute %d incorrectly changed advisory or proof: %+v %+v", tc.minutes, out.Results[1], f)
		}
	}
}

func TestInventoryGapKeepsCurrentPodEventsWithoutRestoringPreGapUsage(t *testing.T) {
	in := fixture(7200, 60)
	in.WindowStart -= 3 * 3600_000
	c := &in.Containers[0]
	c.PreviousReleases = []PreviousRelease{previousFixture("previous", epoch-60_000, 7200, 60)}
	c.Identity.ReleaseStartInferred = true
	c.Identity.ReleaseStartedAt = epoch + 60*60000
	c.Identity.UsageStart = in.EvaluationTime - 3*60000
	c.Inventory.CurrentPods = map[string]int64{"pod-1": epoch + 75*60000}
	c.Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Periods: []Series{guardCounter("intervening", "B", epoch+50*60000, []float64{1})}}}
	beforeB := oomKill("before-B", epoch+30*60000, 512*mib)
	early := oomKill("after-B", epoch+55*60000, 512*mib)
	retired := oomKill("retired", epoch+70*60000, 1024*mib)
	retired.PodUID = "retired"
	c.OOMKills = []OOMKill{retired, early, beforeB}
	p := safetyPolicy(DefaultPolicy())
	p.Classification = &ClassificationPolicy{}
	out := run(t, in, p)
	mem, cpu := out.Results[0], out.Results[1]
	if !slices.Equal(mem.Evidence.OOMKills, []OOMKill{early}) || mem.OOMAdjustment == nil || mem.OOMAdjustment.OOMRequestFloorBytes != 768*mib || mem.Evidence.Identity.ReleaseStartedAt != c.Identity.ReleaseStartedAt {
		t.Fatalf("gap changed event attribution or release identity: %+v", mem)
	}
	if mem.RolloutFallback != nil || cpu.RolloutFallback != nil || len(cpu.Recommendations) != 0 || cpu.DataQuality.ObservedStart < c.Identity.UsageStart {
		t.Fatalf("an early OOM reopened pre-gap usage or fallback: %+v %+v", cpu, mem)
	}
	if class := out.Classifications[0]; class.WindowStart > early.Timestamp || !slices.Equal(finding(class, FeatureOOMKilled).OOMKills, []OOMKill{early}) {
		t.Fatalf("classification disagrees about an observed early OOM: %+v", class)
	}
}

func TestOOMCoverageStartFollowsCFSOnlyRollback(t *testing.T) {
	in := fixture(7200, 60)
	c := &in.Containers[0]
	c.Identity.ReleaseStartInferred = true
	c.Classification = &ClassificationObservation{Throttling: CPUThrottlingObservation{Periods: []Series{guardCounter("intervening", "B", epoch+10*60000, []float64{1})}}}
	p := safetyPolicy(shortPolicy())
	for _, tc := range []struct {
		since int64
		held  bool
	}{{10, false}, {20, true}} {
		c.OOMCoverageStart = epoch + tc.since*60000
		out := run(t, in, p)
		mem := out.Results[0]
		if has(mem.DataQuality, ReasonOOMCoverageIncomplete) != tc.held || (len(mem.Recommendations) == 0) != tc.held || len(out.Results[1].Recommendations) == 0 {
			t.Fatalf("coverage at %d, held=%v: %+v", tc.since, tc.held, mem)
		}
	}
}
