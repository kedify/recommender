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
	capped := p
	capped.Memory.Bounds.Maximum = 128 * mib
	if r := run(t, in, capped).Results[0]; len(r.Recommendations) != 0 {
		t.Fatalf("a policy maximum below current usage authorized a reduction: %+v", r)
	}
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
	for _, unset := range []bool{false, true} {
		if unset {
			c.CPU.CurrentLimit = Signal{Available: true, Unset: true, Timestamp: in.EvaluationTime}
			c.Classification = nil
		}
		r := run(t, in, p).Results[1]
		if _, ok := guardRecommendation(r, SettingLimits); ok || !slices.Contains(r.Notices, ReasonCPULimitBelowDemand) {
			t.Fatalf("unset=%v: %+v", unset, r)
		}
	}
	setUsage(false)
	r := run(t, in, p).Results[1]
	if limit, ok := guardRecommendation(r, SettingLimits); !ok || limit.SuggestedValue < 99.99 || limit.SuggestedValue > 100.01 {
		t.Fatalf("healthy introduction incorrectly required CFS: %+v", r)
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
