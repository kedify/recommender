// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

const mib = 1024 * 1024

func oomKill(id string, timestamp int64, limit float64) OOMKill {
	return OOMKill{ID: id, PodUID: "pod-1", WorkloadUID: "uid", Release: "A", Timestamp: timestamp, MemoryLimitBytes: limit}
}

func TestOOMUsesFailedLimitAndReportsEvidence(t *testing.T) {
	in := fixture(600, 60)
	p := shortPolicy()
	p.Memory.LimitsToRequestsRatio = 1 // KRR's equal memory request and limit.
	baseline := run(t, in, p)
	// Historical event time, outside the current-signal freshness interval.
	kill := oomKill("pod-1/oom-1", epoch+60000, 512*mib)
	in.Containers[0].OOMKills = []OOMKill{kill}
	out := run(t, in, p)
	r := out.Results[0]
	if len(r.Recommendations) != 2 {
		t.Fatalf("expected memory request and limit: %+v", r)
	}
	for _, rec := range r.Recommendations {
		if rec.SuggestedValue != 768*mib || rec.Confidence != 95 {
			t.Fatalf("OOM sizing must use failed limit plus 50%%: %+v", rec)
		}
	}
	if r.DataQuality.Status != DataQualityAvailable || !reflect.DeepEqual(r.Notices, []Reason{ReasonOOMKillDetected}) {
		t.Fatalf("OOM notice must not degrade otherwise complete evidence: %+v", r)
	}
	if !reflect.DeepEqual(r.Evidence.OOMKills, []OOMKill{kill}) || r.Evidence.AggregatedUsage != baseline.Results[0].Evidence.AggregatedUsage {
		t.Fatalf("OOM evidence replaced or contaminated usage evidence: %+v", r.Evidence)
	}
	wantAdjustment := &OOMAdjustment{BaselineRequestBytes: 24 * mib, OOMRequestFloorBytes: 768 * mib}
	if !reflect.DeepEqual(r.OOMAdjustment, wantAdjustment) {
		t.Fatalf("wrong sizing explanation: %+v", r.OOMAdjustment)
	}
	if !reflect.DeepEqual(out.Results[1], baseline.Results[1]) {
		t.Fatal("OOM changed CPU analysis")
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"oom-kill-detected"`, `"oomKills"`, `"memoryLimitBytes":536870912`, `"oomRequestFloorBytes":805306368`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("output omits OOM evidence %s: %s", field, encoded)
		}
	}
	inputJSON, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Input
	if err = json.Unmarshal(inputJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(run(t, decoded, p), out) {
		t.Fatal("JSON adapters do not produce equivalent OOM analysis")
	}
}

func TestOOMKilledCoefficientDoesNotCompoundOrReduceUsageSizing(t *testing.T) {
	for _, peak := range []float64{20 * mib, 800 * mib} {
		in := fixture(600, 60)
		for i := range in.Containers[0].Memory.Series[0].Samples {
			in.Containers[0].Memory.Series[0].Samples[i].Value = peak
		}
		in.Containers[0].OOMKills = []OOMKill{
			oomKill("oom-1", epoch+60000, 256*mib),
			oomKill("oom-2", epoch+120000, 512*mib),
			oomKill("oom-3", epoch+180000, 128*mib),
		}
		p := shortPolicy()
		p.Memory.OOMKilledCoefficient = 1.5
		p.Memory.LimitsToRequestsRatio = 2
		r := run(t, in, p).Results[0]
		wantRequest := math.Max(peak*1.2, 768*mib)
		if len(r.Recommendations) != 2 || r.Recommendations[0].SuggestedValue != wantRequest || r.Recommendations[1].SuggestedValue != wantRequest*2 {
			t.Fatalf("incorrect combination of usage, OOMs, or limit ratio: %+v", r)
		}
		if r.OOMAdjustment.OOMRequestFloorBytes != 768*mib {
			t.Fatalf("OOM adjustment compounded across events: %+v", r.OOMAdjustment)
		}
	}
}

func TestOOMTimestampOnlyFallback(t *testing.T) {
	tests := []struct {
		name         string
		request      float64
		limit        float64
		wantSettings []Setting
		floor        float64
	}{
		{"growth", 20 * mib, 24 * mib, []Setting{SettingRequests, SettingLimits}, 36 * mib},
		{"current limit fallback", 256 * mib, 512 * mib, []Setting{SettingRequests, SettingLimits}, 768 * mib},
		{"no new finite limit", 20 * mib, 0, []Setting{SettingRequests}, 30 * mib},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixture(600, 60)
			c := &in.Containers[0]
			c.Memory.CurrentRequest.Value = tt.request
			c.Memory.CurrentLimit.Value = tt.limit
			c.OOMKills = []OOMKill{oomKill("oom-1", epoch+60000, 0), oomKill("oom-2", epoch+120000, 0)}
			r := run(t, in, shortPolicy()).Results[0]
			if r.OOMAdjustment == nil || !r.OOMAdjustment.UsedCurrentFallback || r.OOMAdjustment.UsedUsageFallback || r.OOMAdjustment.OOMRequestFloorBytes != tt.floor {
				t.Fatalf("timestamp-only kills must apply one 50%% buffer to current settings: %+v", r)
			}
			if r.DataQuality.Status != DataQualityPartial || !has(r.DataQuality, ReasonOOMLimitUnknown) {
				t.Fatalf("unknown failed limit was hidden: %+v", r)
			}
			if len(r.Recommendations) != len(tt.wantSettings) {
				t.Fatalf("unexpected actions: %+v", r)
			}
			for i, rec := range r.Recommendations {
				want := tt.floor
				if rec.Setting == SettingLimits {
					want *= 3
				}
				if rec.Setting != tt.wantSettings[i] || rec.SuggestedValue != want {
					t.Fatalf("incorrect fallback recommendation: %+v", rec)
				}
			}
			if len(tt.wantSettings) == 0 && r.NoActionReason != ReasonOOMLimitUnknown {
				t.Fatalf("missing reason for suppressed downsize: %+v", r)
			}
		})
	}

	in := fixture(600, 60)
	in.Containers[0].OOMKills = []OOMKill{oomKill("known", epoch+60000, 512*mib), oomKill("unknown", epoch+120000, 0)}
	r := run(t, in, shortPolicy()).Results[0]
	if len(r.Recommendations) != 2 || r.Recommendations[0].SuggestedValue != 768*mib || !r.OOMAdjustment.UsedCurrentFallback {
		t.Fatalf("known event must still justify growth alongside incomplete evidence: %+v", r)
	}
}

func TestOOMFiltersIdentityWindowAndReleaseSegment(t *testing.T) {
	for _, mode := range []string{"other UID", "other release", "before window", "future", "before release", "before inferred rollback"} {
		t.Run(mode, func(t *testing.T) {
			in := fixture(1200, 60)
			c := &in.Containers[0]
			kill := oomKill("oom", epoch+300000, 512*mib)
			switch mode {
			case "other UID":
				kill.WorkloadUID = "deleted-workload"
			case "other release":
				kill.Release = "old"
			case "before window":
				kill.Timestamp = in.WindowStart - 1
			case "future":
				kill.Timestamp = in.EvaluationTime + 1
			case "before release":
				c.Identity.ReleaseStartedAt = epoch + 600000
			case "before inferred rollback":
				c.Identity.ReleaseStartedAt = 0
				c.Memory.Series = append(c.Memory.Series, Series{ID: "release-B", WorkloadUID: "uid", Release: "B", Kind: SampleGauge, Samples: []Sample{{Timestamp: epoch + 599999, Value: 1}}})
			}
			baseline := run(t, in, shortPolicy())
			c.OOMKills = []OOMKill{kill}
			if got := run(t, in, shortPolicy()); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("irrelevant OOM altered analysis: %+v", got.Results[0])
			}
		})
	}
	for _, ts := range []int64{epoch, epoch + 600000} {
		in := fixture(600, 60)
		in.Containers[0].OOMKills = []OOMKill{oomKill("boundary", ts, 512*mib)}
		if r := run(t, in, shortPolicy()).Results[0]; len(r.Evidence.OOMKills) != 1 {
			t.Fatalf("OOM at inclusive boundary was lost: %+v", r)
		}
	}
}

func TestOOMDoesNotBypassIdentityAndCurrentSettingGuards(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input, *Policy)
	}{
		{"stale identity", func(in *Input, _ *Policy) { in.Containers[0].Identity.Timestamp = epoch }},
		{"ambiguous identity", func(in *Input, _ *Policy) { in.Containers[0].Identity.Ambiguous = true }},
		{"missing request", func(in *Input, _ *Policy) { in.Containers[0].Memory.CurrentRequest = Signal{} }},
		{"stale request", func(in *Input, _ *Policy) { in.Containers[0].Memory.CurrentRequest.Timestamp = epoch }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixture(600, 60)
			in.Containers[0].OOMKills = []OOMKill{oomKill("oom", epoch+60000, 512*mib)}
			p := shortPolicy()
			tt.mutate(&in, &p)
			r := run(t, in, p).Results[0]
			if len(r.Recommendations) != 0 || r.NoActionReason == "" || r.OOMAdjustment != nil {
				t.Fatalf("OOM bypassed evidence guard: %+v", r)
			}
			if len(r.Evidence.OOMKills) != 1 || !reflect.DeepEqual(r.Notices, []Reason{ReasonOOMKillDetected}) {
				t.Fatalf("blocked analysis must still report OOM evidence: %+v", r)
			}
		})
	}
}

func TestOOMRespectsBoundsInventoryAndRequestOnlyPolicy(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	c.OOMKills = []OOMKill{oomKill("oom", epoch+60000, 512*mib)}
	c.Inventory.Available = false
	p := shortPolicy()
	p.Memory.Bounds.Maximum = 600 * mib
	r := run(t, in, p).Results[0]
	if len(r.Recommendations) != 2 || !has(r.DataQuality, ReasonBounds) || !has(r.DataQuality, ReasonUnknownInventory) {
		t.Fatalf("bounded growth with partial inventory failed: %+v", r)
	}
	for _, rec := range r.Recommendations {
		if rec.SuggestedValue != 600*mib {
			t.Fatalf("OOM escaped resource maximum: %+v", rec)
		}
	}
	p.Memory.RequestsOnly = true
	r = run(t, in, p).Results[0]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonBounds {
		t.Fatalf("request-only advice exceeded retained limit: %+v", r)
	}
	c.Memory.CurrentLimit.Value = 1024 * mib
	r = run(t, in, p).Results[0]
	if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
		t.Fatalf("request-only policy changed limit: %+v", r)
	}

	in = fixture(600, 60)
	c = &in.Containers[0]
	c.OOMKills = []OOMKill{oomKill("oom", epoch+60000, 512*mib)}
	c.Memory.CurrentRequest.Value = 630 * mib
	c.Memory.CurrentLimit.Value = 1900 * mib
	p = shortPolicy()
	p.Memory.OOMKilledCoefficient = 1.25
	r = run(t, in, p).Results[0]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonNoMaterialChange || len(r.Notices) != 1 {
		t.Fatalf("OOM bypassed material-change thresholds or lost its notice: %+v", r)
	}
}

func TestOOMDeterminismDeduplicationAndValidation(t *testing.T) {
	in := fixture(600, 60)
	in.Containers[0].OOMKills = []OOMKill{oomKill("b", epoch+120000, 512*mib), oomKill("a", epoch+60000, 256*mib), oomKill("c", epoch+120000, 128*mib)}
	before, _ := json.Marshal(in)
	want := run(t, in, shortPolicy())
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Fatal("OOM input was mutated")
	}
	kills := in.Containers[0].OOMKills
	in.Containers[0].OOMKills = []OOMKill{kills[2], kills[1], kills[0], kills[0]}
	if got := run(t, in, shortPolicy()); !reflect.DeepEqual(got, want) {
		t.Fatal("event ordering or repeated observations changed output")
	}
	for _, mode := range []string{"missing ID", "missing UID", "missing release", "zero timestamp", "negative timestamp", "negative limit", "NaN limit", "infinite limit", "conflict", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			in := fixture(600, 60)
			kill := oomKill("oom", epoch+60000, 512*mib)
			switch mode {
			case "missing ID":
				kill.ID = ""
			case "missing UID":
				kill.WorkloadUID = ""
			case "missing release":
				kill.Release = ""
			case "zero timestamp":
				kill.Timestamp = 0
			case "negative timestamp":
				kill.Timestamp = -1
			case "negative limit":
				kill.MemoryLimitBytes = -1
			case "NaN limit":
				kill.MemoryLimitBytes = math.NaN()
			case "infinite limit":
				kill.MemoryLimitBytes = math.Inf(1)
			case "overflow":
				kill.MemoryLimitBytes = math.MaxFloat64
			}
			in.Containers[0].OOMKills = []OOMKill{kill}
			if mode == "conflict" {
				kill.MemoryLimitBytes++
				in.Containers[0].OOMKills = append(in.Containers[0].OOMKills, kill)
			}
			if _, err := Analyze(in, shortPolicy()); err == nil || !strings.Contains(err.Error(), "OOM") {
				t.Fatalf("invalid OOM input was accepted: %v", err)
			}
		})
	}
}

func TestOOMValidatesObservationsBeforeFiltering(t *testing.T) {
	for _, scope := range []struct {
		name   string
		mutate func(*OOMKill)
	}{
		{"before window", func(k *OOMKill) { k.Timestamp = epoch - 1 }},
		{"before release", func(k *OOMKill) { k.Timestamp = epoch + 1 }},
		{"future", func(k *OOMKill) { k.Timestamp = epoch + 600001 }},
		{"other workload", func(k *OOMKill) { k.WorkloadUID = "other" }},
		{"other release", func(k *OOMKill) { k.Release = "B" }},
	} {
		for _, invalid := range []struct {
			name   string
			mutate func(*OOMKill)
		}{
			{"missing ID", func(k *OOMKill) { k.ID = "" }},
			{"missing UID", func(k *OOMKill) { k.WorkloadUID = "" }},
			{"missing release", func(k *OOMKill) { k.Release = "" }},
			{"negative limit", func(k *OOMKill) { k.MemoryLimitBytes = -1 }},
			{"NaN limit", func(k *OOMKill) { k.MemoryLimitBytes = math.NaN() }},
			{"infinite limit", func(k *OOMKill) { k.MemoryLimitBytes = math.Inf(1) }},
		} {
			t.Run(scope.name+"/"+invalid.name, func(t *testing.T) {
				in := fixture(600, 60)
				in.Containers[0].Identity.ReleaseStartedAt = epoch + 60000
				kill := oomKill("oom", epoch+120000, 512*mib)
				scope.mutate(&kill)
				invalid.mutate(&kill)
				in.Containers[0].OOMKills = []OOMKill{kill}
				if _, err := Analyze(in, shortPolicy()); err == nil || !strings.Contains(err.Error(), "OOM") {
					t.Fatalf("invalid filtered OOM was accepted: %v", err)
				}
			})
		}
		t.Run(scope.name+"/conflicting ID", func(t *testing.T) {
			in := fixture(600, 60)
			in.Containers[0].Identity.ReleaseStartedAt = epoch + 60000
			selected := oomKill("oom", epoch+120000, 512*mib)
			filtered := selected
			scope.mutate(&filtered)
			conflicting := filtered
			conflicting.MemoryLimitBytes++
			for _, kills := range [][]OOMKill{{selected, filtered}, {filtered, selected}, {filtered, conflicting}} {
				in.Containers[0].OOMKills = kills
				if _, err := Analyze(in, shortPolicy()); err == nil || !strings.Contains(err.Error(), "conflicting observations for OOM kill") {
					t.Fatalf("conflicting filtered OOMs were accepted: %v", err)
				}
			}
			in.Containers[0].OOMKills = []OOMKill{filtered, filtered}
			if r := run(t, in, shortPolicy()).Results[0]; len(r.Evidence.OOMKills) != 0 {
				t.Fatalf("valid filtered duplicates affected sizing: %+v", r)
			}
		})
	}
}

func TestOOMPolicyNormalizationAndIdentity(t *testing.T) {
	for _, coefficient := range []float64{0, 1, 1.25, 2} {
		p, err := NormalizePolicy(Policy{Memory: MemoryPolicy{OOMKilledCoefficient: coefficient}})
		if err != nil {
			t.Fatal(err)
		}
		want := coefficient
		if coefficient == 0 {
			want = 1.5
		}
		if p.Memory.OOMKilledCoefficient != want {
			t.Fatalf("normalized OOM coefficient = %v, want %v", p.Memory.OOMKilledCoefficient, want)
		}
	}
	for _, coefficient := range []float64{-1, .99, math.NaN(), math.Inf(1)} {
		if _, err := NormalizePolicy(Policy{Memory: MemoryPolicy{OOMKilledCoefficient: coefficient}}); err == nil {
			t.Fatalf("invalid OOM coefficient accepted: %v", coefficient)
		}
	}
	defaultVersion, err := PolicyVersion(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	customVersion, err := PolicyVersion(Policy{Memory: MemoryPolicy{OOMKilledCoefficient: 1.25}})
	if err != nil || customVersion == defaultVersion {
		t.Fatalf("OOM policy not included in policy identity: %s, %v", customVersion, err)
	}
}

func TestOOMBypassesUsageRequirements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Input, *Policy)
	}{
		{"no metrics or live pods", func(in *Input, _ *Policy) {
			in.Containers[0].Memory.Series = nil
			in.Containers[0].CPU.Series = nil
			in.Containers[0].Inventory.Eligible = 0
			in.Containers[0].Inventory.Observed = 0
		}},
		{"one observation", func(in *Input, _ *Policy) {
			in.Containers[0].Memory.Series[0].Samples = in.Containers[0].Memory.Series[0].Samples[:1]
		}},
		{"insufficient history", func(_ *Input, p *Policy) { p.Evidence.MinimumHistorySeconds = 3600 }},
		{"insufficient observations", func(_ *Input, p *Policy) { p.Evidence.MinimumSamples = 1000 }},
		{"stale usage", func(in *Input, _ *Policy) {
			in.Containers[0].Memory.Series[0].Samples = in.Containers[0].Memory.Series[0].Samples[:2]
		}},
		{"sparse coverage", func(in *Input, _ *Policy) {
			s := &in.Containers[0].Memory.Series[0]
			s.Samples = append(s.Samples[:2], s.Samples[len(s.Samples)-2:]...)
		}},
		{"infer rollout from OOM", func(in *Input, _ *Policy) {
			in.Containers[0].Identity.ReleaseStartedAt = 0
			in.Containers[0].CPU.Series = nil
			in.Containers[0].Memory.Series = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, failedLimit := range []float64{0, 50 * mib} {
				in, p := fixture(600, 60), shortPolicy()
				p.Memory.LimitsToRequestsRatio = 1
				c := &in.Containers[0]
				c.Memory.CurrentRequest.Value, c.Memory.CurrentLimit.Value = 50*mib, 50*mib
				tc.mutate(&in, &p)
				c.OOMKills = []OOMKill{oomKill("oom", epoch+60000, failedLimit)}
				r := run(t, in, p).Results[0]
				if r.DataQuality.Status != DataQualityPartial || len(r.Recommendations) != 2 || r.OOMAdjustment == nil {
					t.Fatalf("OOM growth blocked by usage quality: %+v", r)
				}
				for _, rec := range r.Recommendations {
					if rec.SuggestedValue != 75*mib || rec.Confidence != 0 {
						t.Fatalf("expected 50Mi × 1.5 without invented usage confidence: %+v", rec)
					}
				}
				if r.DecisionTrace.Source.Method != "OOM kill" {
					t.Fatal("missing OOM decision source")
				}
			}
		})
	}
}

func TestOOMWithoutUsageCannotDownsizeOrInventBaseline(t *testing.T) {
	in, p := fixture(600, 60), shortPolicy()
	c := &in.Containers[0]
	c.Memory.Series = nil
	c.OOMKills = []OOMKill{oomKill("oom", epoch+60000, 50*mib)}
	c.Memory.CurrentRequest.Value, c.Memory.CurrentLimit.Value = 512*mib, 2048*mib
	if r := run(t, in, p).Results[0]; len(r.Recommendations) != 0 {
		t.Fatalf("old low limit justified a reduction without usage: %+v", r)
	}
	c.OOMKills[0].MemoryLimitBytes = 0
	c.Memory.CurrentRequest = Signal{Available: true, Unset: true, Timestamp: in.EvaluationTime}
	c.Memory.CurrentLimit = c.Memory.CurrentRequest
	if r := run(t, in, p).Results[0]; r.DataQuality.Status != DataQualityUnavailable || len(r.Recommendations) != 0 {
		t.Fatalf("invented a baseline without usage or allocations: %+v", r)
	}
}
