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

func leakFixture(hours int64, profile func(float64) float64) Input {
	in := fixture(hours*3600, 60)
	for i := range in.Containers[0].Memory.Series[0].Samples {
		s := &in.Containers[0].Memory.Series[0].Samples[i]
		s.Value = profile(float64(s.Timestamp-epoch)/3600000) * mib
	}
	return in
}

func leakPolicy() Policy {
	p := DefaultPolicy()
	p.Memory.LeakDetection = &MemoryLeakPolicy{}
	return p
}

func TestMemoryLeakProfiles(t *testing.T) {
	profiles := []struct {
		name    string
		profile func(float64) float64
		want    MemoryLeakStatus
	}{
		{"linear", func(h float64) float64 { return 100 + 12*h }, MemoryLeakPotential},
		{"rising GC floors", func(h float64) float64 { return 100 + 12*h + 48*math.Mod(h*6, 1) }, MemoryLeakPotential},
		{"staircase with GC", func(h float64) float64 { return 100 + 24*math.Floor(h) + 32*math.Mod(h*6, 1) }, MemoryLeakPotential},
		{"flat", func(float64) float64 { return 128 }, MemoryLeakNoPattern},
		{"bounded GC", func(h float64) float64 { return 128 + 64*math.Mod(h*6, 1) }, MemoryLeakNoPattern},
		{"long bounded GC cycles", func(h float64) float64 { return 128 + 128*math.Mod(h, 2) }, MemoryLeakNoPattern},
		{"startup allocation", func(h float64) float64 { return 100 + 300*math.Min(h, 1) }, MemoryLeakNoPattern},
		{"one permanent step", func(h float64) float64 {
			if h < 12 {
				return 100
			}
			return 500
		}, MemoryLeakNoPattern},
		{"cache plateau", func(h float64) float64 { return 100 + 12*math.Min(h, 16) }, MemoryLeakNoPattern},
		{"recent cache plateau", func(h float64) float64 { return 100 + 12*math.Min(h, 20) }, MemoryLeakNoPattern},
		{"recovery", func(h float64) float64 {
			if h < 18 {
				return 100 + 12*h
			}
			return 100
		}, MemoryLeakNoPattern},
		{"falling", func(h float64) float64 { return 500 - 12*h }, MemoryLeakNoPattern},
		{"small drift", func(h float64) float64 { return 100 + .5*h }, MemoryLeakNoPattern},
		{"small relative growth", func(h float64) float64 { return 10000 + 12*h }, MemoryLeakNoPattern},
		{"increasing transient peaks", func(h float64) float64 {
			if int(math.Round(h*60))%30 == 0 {
				return 500 + 100*h
			}
			return 100
		}, MemoryLeakNoPattern},
		{"bounded noisy baseline", func(h float64) float64 { return 200 + 10*math.Sin(h*37) + 5*math.Cos(h*11) }, MemoryLeakNoPattern},
	}
	for _, tt := range profiles {
		t.Run(tt.name, func(t *testing.T) {
			in := leakFixture(24, tt.profile)
			r := run(t, in, leakPolicy()).Results[0]
			leak := r.MemoryLeak
			if leak == nil || leak.Status != tt.want || leak.EvaluatedEpisodes != 1 || len(leak.Episodes) != 1 {
				t.Fatalf("unexpected leak analysis: %+v", leak)
			}
			if leak.DetectorVersion != MemoryLeakDetectorVersion || leak.Episodes[0].BucketCount != 47 || leak.Episodes[0].Coverage < .99 {
				t.Fatalf("missing measured evidence: %+v", leak)
			}
			if tt.want == MemoryLeakPotential {
				if !reflect.DeepEqual(r.Notices, []Reason{ReasonPotentialMemoryLeak}) || leak.SuspectedEpisodes != 1 || leak.Episodes[0].SlopeBytesPerHour <= 0 {
					t.Fatalf("missing potential leak notice/evidence: %+v", r)
				}
			} else if len(r.Notices) != 0 {
				t.Fatalf("non-leak profile generated a notice: %+v", r)
			}
			if _, err := json.Marshal(r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryLeakIsOptionalAdvisoryAndIndependentOfSizingHistory(t *testing.T) {
	in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
	p := leakPolicy()
	p.Evidence.MinimumHistorySeconds = 7 * 86400
	baselinePolicy := p
	baselinePolicy.Memory.LeakDetection = nil
	baseline := run(t, in, baselinePolicy)
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"memoryLeak"`) || strings.Contains(string(encoded), `"leakDetection"`) {
		t.Fatal("disabled detection leaked fields into existing output")
	}
	out := run(t, in, p)
	if out.Results[0].MemoryLeak.Status != MemoryLeakPotential || !has(out.Results[0].DataQuality, ReasonInsufficientHistory) {
		t.Fatal("leak detection must use its own shorter history without bypassing sizing guards")
	}
	for i := range out.Results {
		actual, want := out.Results[i], baseline.Results[i]
		actual.MemoryLeak, actual.Notices = nil, nil
		if !reflect.DeepEqual(actual, want) {
			t.Fatalf("leak detection changed resource sizing: %+v", actual)
		}
	}
	if out.Results[1].MemoryLeak != nil {
		t.Fatal("CPU received memory leak analysis")
	}
	in.Containers[0].Memory.CurrentRequest = Signal{}
	if run(t, in, leakPolicy()).Results[0].MemoryLeak.Status != MemoryLeakPotential {
		t.Fatal("leak detection unnecessarily depends on configured resource requests")
	}
}

func TestMemoryLeakUsesEachReplicaAndLifetimeSeparately(t *testing.T) {
	in := leakFixture(24, func(float64) float64 { return 100 })
	c := &in.Containers[0]
	busy := c.Memory.Series[0]
	busy.ID, busy.PodUID = "busy", "busy-pod"
	busy.Samples = append([]Sample(nil), busy.Samples...)
	for i := range busy.Samples {
		busy.Samples[i].Value = (100 + 12*float64(i)/60) * mib
	}
	c.Memory.Series = append(c.Memory.Series, busy)
	r := run(t, in, leakPolicy()).Results[0].MemoryLeak
	if r.Status != MemoryLeakPotential || r.EvaluatedEpisodes != 2 || r.SuspectedEpisodes != 1 || r.Episodes[0].SeriesID != "busy" {
		t.Fatalf("busy replica was pooled or hidden: %+v", r)
	}
	// Replacement raises the absolute allocation level, but neither lifetime grows.
	in = leakFixture(24, func(float64) float64 { return 100 })
	c = &in.Containers[0]
	old := c.Memory.Series[0]
	old.Samples = append([]Sample(nil), old.Samples[:12*60]...)
	replacement := c.Memory.Series[0]
	replacement.ID, replacement.PodUID = "replacement", "new-pod"
	replacement.Samples = append([]Sample(nil), replacement.Samples[12*60:]...)
	for i := range replacement.Samples {
		replacement.Samples[i].Value = 500 * mib
	}
	c.Memory.Series = []Series{old, replacement}
	c.OOMKills = []OOMKill{oomKill("old-pod-oom", epoch+12*3600000-1, 128*mib)}
	r = run(t, in, leakPolicy()).Results[0].MemoryLeak
	if r.Status != MemoryLeakNoPattern || r.EvaluatedEpisodes != 2 {
		t.Fatalf("replica replacement manufactured a trend: %+v", r)
	}
	// The same pod can have separate container lifetimes, too.
	c.Memory.Series[1].PodUID = old.PodUID
	if r = run(t, in, leakPolicy()).Results[0].MemoryLeak; r.Status != MemoryLeakNoPattern {
		t.Fatalf("container lifetime change manufactured a trend: %+v", r)
	}
}

func TestMemoryLeakPreservesEligibleRecommendationsAndOOMAdjustment(t *testing.T) {
	for _, withOOM := range []bool{false, true} {
		in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
		if withOOM {
			in.Containers[0].OOMKills = []OOMKill{oomKill("terminal", in.EvaluationTime, 512*mib)}
		}
		p := DefaultPolicy()
		p.Evidence.MinimumHistorySeconds = 6 * 3600
		baseline := run(t, in, p)
		if len(baseline.Results[0].Recommendations) == 0 {
			t.Fatal("fixture must exercise eligible memory sizing")
		}
		p.Memory.LeakDetection = &MemoryLeakPolicy{}
		out := run(t, in, p)
		if out.Results[0].MemoryLeak.Status != MemoryLeakPotential {
			t.Fatal("fixture must produce a leak finding")
		}
		for i := range out.Results {
			actual, want := out.Results[i], baseline.Results[i]
			actual.MemoryLeak, actual.Notices = nil, want.Notices
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("advisory diagnostic changed recommendations or OOM adjustment: %+v", actual)
			}
		}
	}
}

func TestMemoryLeakCustomPolicy(t *testing.T) {
	in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
	p := leakPolicy()
	p.Memory.LeakDetection = &MemoryLeakPolicy{
		LookbackSeconds: 12 * 3600, BucketDurationSeconds: 15 * 60,
		MinimumHistorySeconds: 3 * 3600, WarmupSeconds: 15 * 60,
		MinimumSamplesPerBucket: 10, MinimumGrowthBytes: 32 * mib,
		MinimumRelativeGrowth: .1, MinimumTrendConsistency: .9,
	}
	leak := run(t, in, p).Results[0].MemoryLeak
	if leak.Status != MemoryLeakPotential || leak.WindowStart != epoch+12*3600000 || leak.Episodes[0].BucketCount != 48 {
		t.Fatalf("custom policy not applied: %+v", leak)
	}
	p.Memory.LeakDetection.MinimumGrowthBytes = 1024 * mib
	if leak = run(t, in, p).Results[0].MemoryLeak; leak.Status != MemoryLeakNoPattern {
		t.Fatalf("custom growth threshold not applied: %+v", leak)
	}
}

func TestMemoryLeakPartitionsReleasesAndLookback(t *testing.T) {
	in := leakFixture(24, func(h float64) float64 {
		if h < 12 {
			return 100 + 40*h
		}
		return 100
	})
	c := &in.Containers[0]
	c.Identity.ReleaseStartedAt = epoch + 12*3600000
	old := c.Memory.Series[0]
	old.ID, old.Release = "old-release", "B"
	old.Samples = append([]Sample(nil), old.Samples[:12*60]...)
	c.Memory.Series = append(c.Memory.Series, old)
	for _, inferred := range []bool{false, true} {
		if inferred {
			c.Identity.ReleaseStartedAt = 0
		}
		r := run(t, in, leakPolicy()).Results[0].MemoryLeak
		if r.Status != MemoryLeakNoPattern || r.WindowStart < epoch+12*3600000 || len(r.Episodes) != 1 {
			t.Fatalf("old release or pre-rollback observations affected diagnosis: %+v", r)
		}
	}
	// A recreated workload with the same name cannot contribute an episode.
	c.Memory.Series[1].WorkloadUID = "deleted-workload"
	c.Identity.ReleaseStartedAt = epoch + 12*3600000
	if r := run(t, in, leakPolicy()).Results[0].MemoryLeak; len(r.Episodes) != 1 || r.Status != MemoryLeakNoPattern {
		t.Fatalf("deleted workload leaked into analysis: %+v", r)
	}
	in = leakFixture(72, func(h float64) float64 {
		if h < 48 {
			return 100 + 40*h
		}
		return 100
	})
	r := run(t, in, leakPolicy()).Results[0].MemoryLeak
	if r.Status != MemoryLeakNoPattern || r.WindowStart != epoch+48*3600000 {
		t.Fatalf("data outside the leak lookback changed analysis: %+v", r)
	}
}

func TestMemoryLeakOOMCorrelationAndEpisodeSplitting(t *testing.T) {
	in := leakFixture(24, func(h float64) float64 { return 100 + 20*math.Mod(h, 12) })
	c := &in.Containers[0]
	c.OOMKills = []OOMKill{
		oomKill("first", epoch+12*3600000-1, 512*mib),
		oomKill("second", in.EvaluationTime, 512*mib),
	}
	r := run(t, in, leakPolicy()).Results[0]
	leak := r.MemoryLeak
	if leak.Status != MemoryLeakPotential || leak.SuspectedEpisodes != 2 || leak.SkippedEpisodes != 0 {
		t.Fatalf("OOM resets obscured repeated leak episodes: %+v", leak)
	}
	for i, e := range leak.Episodes {
		if !reflect.DeepEqual(e.OOMKillIDs, []string{c.OOMKills[i].ID}) || len(e.Reasons) != 2 || e.Reasons[1] != ReasonOOMKillDetected {
			t.Fatalf("missing episode-specific OOM corroboration: %+v", e)
		}
	}
	if !reflect.DeepEqual(r.Notices, []Reason{ReasonOOMKillDetected, ReasonPotentialMemoryLeak}) {
		t.Fatalf("OOM and leak notices should coexist: %+v", r.Notices)
	}
	// An OOM on a flat profile does not prove a leak.
	in = leakFixture(24, func(float64) float64 { return 200 })
	in.Containers[0].OOMKills = []OOMKill{oomKill("flat-oom", in.EvaluationTime, 256*mib)}
	if r = run(t, in, leakPolicy()).Results[0]; r.MemoryLeak.Status != MemoryLeakNoPattern || len(r.Notices) != 1 {
		t.Fatalf("OOM alone was treated as a leak: %+v", r)
	}
	for _, mode := range []string{"different pod", "unknown pod", "distant event"} {
		t.Run(mode, func(t *testing.T) {
			in := leakFixture(24, func(h float64) float64 { return 100 + 20*h })
			in.Containers[0].Memory.Series[0].Samples = in.Containers[0].Memory.Series[0].Samples[:12*60]
			kill := oomKill("oom", epoch+12*3600000-1, 512*mib)
			switch mode {
			case "different pod":
				kill.PodUID = "unrelated"
			case "unknown pod":
				kill.PodUID = ""
			case "distant event":
				kill.Timestamp = in.EvaluationTime
			}
			in.Containers[0].OOMKills = []OOMKill{kill}
			leak := run(t, in, leakPolicy()).Results[0].MemoryLeak
			if leak.Status != MemoryLeakInsufficientData || len(leak.Episodes[0].OOMKillIDs) != 0 {
				t.Fatalf("unrelated OOM made stale evidence eligible: %+v", leak)
			}
		})
	}
}

func TestMemoryLeakInsufficientEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		reason Reason
	}{
		{"short history", func(in *Input) { *in = leakFixture(3, func(h float64) float64 { return 100 + 100*h }) }, ReasonMemoryLeakBuckets},
		{"no usage", func(in *Input) { in.Containers[0].Memory.Series = nil }, ReasonMissingUsage},
		{"stale identity", func(in *Input) { in.Containers[0].Identity.Timestamp = epoch }, ReasonStaleIdentity},
		{"ambiguous identity", func(in *Input) { in.Containers[0].Identity.Ambiguous = true }, ReasonAmbiguousIdentity},
		{"unknown series identity", func(in *Input) { in.Containers[0].Memory.Series[0].Release = "" }, ReasonUnknownSeriesIdentity},
		{"stale samples", func(in *Input) {
			s := &in.Containers[0].Memory.Series[0]
			s.Samples = s.Samples[:len(s.Samples)-10]
		}, ReasonStaleUsage},
		{"insufficient episode coverage", func(in *Input) {
			s := &in.Containers[0].Memory.Series[0]
			s.Samples = append(s.Samples[:12*60], s.Samples[16*60:]...)
		}, ReasonSparseCoverage},
		{"sparse coverage", func(in *Input) {
			s := &in.Containers[0].Memory.Series[0]
			var kept []Sample
			for i, v := range s.Samples {
				if i%5 != 0 {
					kept = append(kept, v)
				}
			}
			s.Samples = kept
		}, ReasonSparseCoverage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
			tt.mutate(&in)
			leak := run(t, in, leakPolicy()).Results[0].MemoryLeak
			if leak.Status != MemoryLeakInsufficientData || !has(DataQuality{Reasons: leak.Reasons}, tt.reason) {
				t.Fatalf("invalid evidence was classified: %+v", leak)
			}
		})
	}
	// Another replica must not supply the first replica's missing coverage.
	in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
	c := &in.Containers[0]
	other := c.Memory.Series[0]
	other.ID, other.PodUID = "healthy", "healthy-pod"
	other.Samples = append([]Sample(nil), other.Samples...)
	for i := range other.Samples {
		other.Samples[i].Value = 100 * mib
	}
	c.Memory.Series[0].Samples = append(c.Memory.Series[0].Samples[:12*60], c.Memory.Series[0].Samples[16*60:]...)
	c.Memory.Series = append(c.Memory.Series, other)
	if leak := run(t, in, leakPolicy()).Results[0].MemoryLeak; leak.Status != MemoryLeakInsufficientData || leak.EvaluatedEpisodes != 1 || leak.SkippedEpisodes != 1 {
		t.Fatalf("replicas pooled coverage or incomplete evidence reported no pattern: %+v", leak)
	}
}

func TestMemoryLeakAccountsForUnusableSeries(t *testing.T) {
	for _, growing := range []bool{false, true} {
		for _, tt := range []struct {
			name   string
			mutate func(*Series)
			reason Reason
		}{
			{"empty", func(s *Series) { s.Samples = nil }, ReasonMissingUsage},
			{"outside lookback", func(s *Series) { s.Samples = s.Samples[:24*60] }, ReasonStaleUsage},
			{"stale within lookback", func(s *Series) { s.Samples = s.Samples[:len(s.Samples)-10] }, ReasonStaleUsage},
		} {
			name := tt.name + "/flat companion"
			if growing {
				name = tt.name + "/growing companion"
			}
			t.Run(name, func(t *testing.T) {
				in := leakFixture(48, func(h float64) float64 {
					if growing {
						return 100 + 12*h
					}
					return 100
				})
				c := &in.Containers[0]
				other := c.Memory.Series[0]
				other.ID, other.PodUID = "unusable", "unusable-pod"
				tt.mutate(&other)
				c.Memory.Series = append(c.Memory.Series, other)
				leak := run(t, in, leakPolicy()).Results[0].MemoryLeak
				want := MemoryLeakInsufficientData
				if growing {
					want = MemoryLeakPotential
				}
				if leak.Status != want || leak.EvaluatedEpisodes != 1 || leak.SkippedEpisodes != 1 || len(leak.Episodes) != 2 {
					t.Fatalf("unusable series was lost: %+v", leak)
				}
				skipped := leak.Episodes[1]
				if skipped.SeriesID != other.ID || skipped.PodUID != other.PodUID || skipped.Status != MemoryLeakInsufficientData || !has(DataQuality{Reasons: skipped.Reasons}, tt.reason) {
					t.Fatalf("missing skipped-series evidence: %+v", skipped)
				}
				if !growing && !has(DataQuality{Reasons: leak.Reasons}, tt.reason) {
					t.Fatalf("missing aggregate reason: %+v", leak)
				}
			})
		}
	}
}

func TestMemoryLeakToleratesCollectionOutages(t *testing.T) {
	for _, minutes := range []int{15, 60} {
		in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
		s := &in.Containers[0].Memory.Series[0]
		s.Samples = append(s.Samples[:12*60], s.Samples[12*60+minutes:]...)
		leak := run(t, in, leakPolicy()).Results[0].MemoryLeak
		if leak.Status != MemoryLeakPotential || leak.SuspectedEpisodes != 1 || leak.Episodes[0].Coverage >= 1 || leak.Episodes[0].Coverage < .9 {
			t.Fatalf("%d-minute collection outage rejected usable trend evidence: %+v", minutes, leak)
		}
		if math.Abs(leak.Episodes[0].SlopeBytesPerHour-12*mib) > 1e-6 {
			t.Fatalf("missing buckets compressed elapsed time: %+v", leak.Episodes[0])
		}
	}
	slope, consistency := memoryBaselineTrend([]float64{100, 112, 148}, []float64{0, 1, 4})
	if slope != 12 || consistency != 1 {
		t.Fatalf("trend must use actual bucket timestamps: slope=%g, consistency=%g", slope, consistency)
	}
}

func TestMemoryLeakDeterminismAndInputImmutability(t *testing.T) {
	in := leakFixture(24, func(h float64) float64 { return 100 + 12*h })
	p := leakPolicy()
	before, _ := json.Marshal(in)
	policyBefore, _ := json.Marshal(p)
	want := run(t, in, p)
	after, _ := json.Marshal(in)
	policyAfter, _ := json.Marshal(p)
	if string(before) != string(after) || string(policyBefore) != string(policyAfter) {
		t.Fatal("analysis mutated input or the caller's optional policy")
	}
	s := &in.Containers[0].Memory.Series[0]
	for i, j := 0, len(s.Samples)-1; i < j; i, j = i+1, j-1 {
		s.Samples[i], s.Samples[j] = s.Samples[j], s.Samples[i]
	}
	s.Samples = append(s.Samples, s.Samples[0])
	if got := run(t, in, p); !reflect.DeepEqual(got, want) {
		t.Fatal("sample ordering or duplicate timestamps changed diagnosis")
	}
	var decoded Input
	if err := json.Unmarshal(before, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := run(t, decoded, p); !reflect.DeepEqual(got, want) {
		t.Fatal("offline and connected inputs differ")
	}
	for _, base := range []float64{0, 1e-320} {
		in = leakFixture(24, func(h float64) float64 {
			if h < 6 {
				return base
			}
			return (h - 6) * 24
		})
		r := run(t, in, p).Results[0]
		if _, err := json.Marshal(r); err != nil {
			t.Fatalf("non-finite leak output: %v", err)
		}
		if base == 0 && (r.MemoryLeak.Status != MemoryLeakPotential || r.MemoryLeak.Episodes[0].RelativeGrowth != nil) {
			t.Fatalf("zero starting baseline mishandled: %+v", r.MemoryLeak)
		}
	}
}

func TestMemoryLeakPolicyValidationAndIdentity(t *testing.T) {
	p := leakPolicy()
	q, err := NormalizePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if *p.Memory.LeakDetection != (MemoryLeakPolicy{}) {
		t.Fatal("normalization mutated caller's pointer")
	}
	if q.Memory.LeakDetection.LookbackSeconds != 86400 || q.Memory.LeakDetection.MinimumGrowthBytes != 64*mib {
		t.Fatalf("wrong defaults: %+v", q.Memory.LeakDetection)
	}
	defaultVersion, _ := PolicyVersion(Policy{})
	enabledVersion, _ := PolicyVersion(p)
	normalizedVersion, _ := PolicyVersion(q)
	if defaultVersion == enabledVersion || enabledVersion != normalizedVersion {
		t.Fatal("optional detector policy identity is not normalized")
	}
	for _, change := range []func(*MemoryLeakPolicy){
		func(p *MemoryLeakPolicy) { p.LookbackSeconds = -1 },
		func(p *MemoryLeakPolicy) { p.LookbackSeconds = math.MaxInt64 },
		func(p *MemoryLeakPolicy) { p.BucketDurationSeconds = 1 },
		func(p *MemoryLeakPolicy) { p.BucketDurationSeconds = 24 * 3600 },
		func(p *MemoryLeakPolicy) { p.MinimumHistorySeconds = 48 * 3600 },
		func(p *MemoryLeakPolicy) { p.WarmupSeconds = 48 * 3600 },
		func(p *MemoryLeakPolicy) { p.MinimumSamplesPerBucket = 1 },
		func(p *MemoryLeakPolicy) { p.MinimumGrowthBytes = math.NaN() },
		func(p *MemoryLeakPolicy) { p.MinimumRelativeGrowth = math.Inf(1) },
		func(p *MemoryLeakPolicy) { p.MinimumTrendConsistency = .5 },
		func(p *MemoryLeakPolicy) { p.MinimumTrendConsistency = 1.1 },
	} {
		p := leakPolicy()
		change(p.Memory.LeakDetection)
		if _, err := NormalizePolicy(p); err == nil || !strings.Contains(err.Error(), "memory.leakDetection") {
			t.Fatalf("invalid leak policy accepted: %+v, %v", p, err)
		}
	}
	q.Memory.LeakDetection.MinimumGrowthBytes *= 10
	if changedVersion, _ := PolicyVersion(q); changedVersion == enabledVersion {
		t.Fatal("threshold not included in policy identity")
	}
}

func TestMemoryBaselineRobustSlope(t *testing.T) {
	slope, consistency := memoryBaselineTrend([]float64{10, 12, 14, 16, 18}, []float64{0, 1, 2, 3, 4})
	if slope != 2 || consistency != 1 {
		t.Fatalf("wrong slope %v or consistency %v", slope, consistency)
	}
	slope, _ = memoryBaselineTrend([]float64{10, 12, 14, 1000, 18, 20, 22}, []float64{0, 1, 2, 3, 4, 5, 6})
	if slope != 2 {
		t.Fatalf("single outlier distorted robust slope: %v", slope)
	}
}
