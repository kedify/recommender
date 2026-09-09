// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

const epoch int64 = 1800000000000

func fixture(duration, step int64) Input {
	end := epoch + duration*1000
	c := ContainerObservation{Target: Target{Namespace: "shop", Kind: "Deployment", Name: "api", Container: "app", WorkloadUID: "uid", Release: "A"}, Identity: CurrentIdentity{Available: true, WorkloadUID: "uid", Release: "A", Timestamp: end, ReleaseStartedAt: epoch}, Inventory: Inventory{Available: true, Timestamp: end, Eligible: 1, Observed: 1}}
	for _, r := range []*ResourceObservation{&c.CPU, &c.Memory} {
		s := Series{ID: "pod-1", PodUID: "pod-1", WorkloadUID: "uid", Release: "A", Kind: SampleGauge}
		for sec := int64(0); sec <= duration; sec += step {
			s.Samples = append(s.Samples, Sample{Timestamp: epoch + sec*1000, Value: 10})
		}
		r.Series = []Series{s}
		r.CurrentRequest = Signal{Available: true, Timestamp: end, Value: 1000}
		r.CurrentLimit = Signal{Available: true, Timestamp: end, Value: 4000}
	}
	for i := range c.Memory.Series[0].Samples {
		c.Memory.Series[0].Samples[i].Value = 20 * 1024 * 1024
	}
	c.Memory.CurrentRequest.Value = 256 * 1024 * 1024
	c.Memory.CurrentLimit.Value = 512 * 1024 * 1024
	return Input{SchemaVersion: InputSchemaVersion, WindowStart: epoch, EvaluationTime: end, Containers: []ContainerObservation{c}}
}
func shortPolicy() Policy {
	p := DefaultPolicy()
	p.Evidence.MinimumHistorySeconds = 600
	p.Evidence.MinimumSamples = 10
	return p
}
func TestPolicyStrategyNormalization(t *testing.T) {
	got, err := NormalizePolicy(Policy{CPU: CPUPolicy{Strategy: " Percentile "}, Memory: MemoryPolicy{Strategy: " Max "}})
	if err != nil || !reflect.DeepEqual(got, DefaultPolicy()) {
		t.Fatalf("strategy normalization changed the effective defaults: %+v, %v", got, err)
	}
}

func TestIdentityBeforeReleaseBoundaryCannotAuthorizeSizing(t *testing.T) {
	in := fixture(1200, 60)
	in.Containers[0].Identity.ReleaseStartedAt = epoch + 600_000
	in.Containers[0].Identity.Timestamp = epoch + 599_000
	p := shortPolicy()
	p.Evidence.FreshnessSeconds = 1200
	for _, result := range run(t, in, p).Results {
		if !has(result.DataQuality, ReasonStaleIdentity) || len(result.Recommendations) != 0 {
			t.Fatalf("pre-release identity authorized sizing: %+v", result)
		}
	}
}
func run(t *testing.T, in Input, p Policy) Output {
	t.Helper()
	out, err := Analyze(in, p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func has(q DataQuality, r Reason) bool {
	for _, x := range q.Reasons {
		if x == r {
			return true
		}
	}
	return false
}
func TestRawOffGridPeakAndCPUPercentile(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	c.Memory.Series[0].Samples = append(c.Memory.Series[0].Samples, Sample{Timestamp: epoch + 233127, Value: 100 * 1024 * 1024})
	for i := range c.CPU.Series[0].Samples {
		c.CPU.Series[0].Samples[i].Value = float64(i * 10)
	}
	p := shortPolicy()
	p.CPU.Percentile = 50
	out := run(t, in, p)
	if out.Results[0].Evidence.AggregatedUsage.Value != 100*1024*1024 || out.Results[1].Evidence.AggregatedUsage.Value != 50 {
		t.Fatalf("raw peak/percentile lost: %+v", out.Results)
	}
	aligned := in
	aligned.EvaluationTime += 15000
	if got := run(t, aligned, p); got.Results[0].Evidence.AggregatedUsage != out.Results[0].Evidence.AggregatedUsage || got.Results[1].Evidence.AggregatedUsage != out.Results[1].Evidence.AggregatedUsage {
		t.Fatal("evaluation alignment changed aggregation")
	}
	// A JSON/offline source produces byte-identical output from equivalent raw input.
	b, _ := json.Marshal(in)
	var decoded Input
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := run(t, decoded, p); !reflect.DeepEqual(out, got) {
		t.Fatal("offline/connected normalized results differ")
	}
}
func TestWeeklyDefaultAndMeasuredCoverage(t *testing.T) {
	tests := []struct {
		name   string
		in     Input
		reason Reason
	}{{"three quiet days", fixture(3*86400, 60), ReasonInsufficientHistory}, {"sparse week", fixture(7*86400, 86400), ReasonInsufficientSamples}, {"stable week", fixture(7*86400, 60), ""}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := run(t, tt.in, Policy{})
			for _, r := range out.Results {
				if tt.reason != "" {
					if !has(r.DataQuality, tt.reason) || len(r.Recommendations) > 0 {
						t.Fatalf("unsafe short/sparse advice: %+v", r)
					}
				} else {
					if len(r.Recommendations) == 0 || r.Recommendations[0].Confidence > 95 {
						t.Fatalf("stable week should size with capped confidence: %+v", r)
					}
				}
			}
		})
	}
	in := fixture(7*86400, 60)
	s := &in.Containers[0].CPU.Series[0]
	s.Samples = s.Samples[len(s.Samples)-20:]
	out := run(t, in, Policy{})
	if out.Results[1].DataQuality.Coverage > .01 || !has(out.Results[1].DataQuality, ReasonInsufficientHistory) || len(out.Results[0].Recommendations) == 0 {
		t.Fatal("requested lookback substituted for observed CPU history or memory blocked")
	}
}
func TestReleaseIdentityPartitions(t *testing.T) {
	for _, mode := range []string{"old-new", "rollback", "recreated", "mixed", "stale-identity", "mismatch", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			in := fixture(600, 60)
			c := &in.Containers[0]
			foreign := c.CPU.Series[0]
			foreign.ID = "foreign"
			foreign.Samples = []Sample{{Timestamp: epoch + 300000, Value: 999999}}
			foreign.Release = "B"
			switch mode {
			case "old-new":
				foreign.Samples[0].Timestamp = epoch - 60000
				c.CPU.Series = append(c.CPU.Series, foreign)
			case "rollback":
				c.Identity.ReleaseStartedAt = 0
				c.CPU.Series = append(c.CPU.Series, foreign)
			case "recreated":
				foreign.WorkloadUID = "old-uid"
				foreign.Release = "A"
				c.CPU.Series = append(c.CPU.Series, foreign)
			case "mixed":
				c.Identity.Ambiguous = true
			case "stale-identity":
				c.Identity.Timestamp = epoch
			case "mismatch":
				c.Identity.Release = "B"
			case "unknown":
				c.Identity.Available = false
			}
			out := run(t, in, shortPolicy())
			r := out.Results[1]
			if mode == "old-new" || mode == "recreated" {
				if r.Evidence.AggregatedUsage.Value != 10 || len(r.Recommendations) == 0 {
					t.Fatalf("identity filtering failed %+v", r)
				}
			} else if len(r.Recommendations) > 0 || r.NoActionReason == "" {
				t.Fatalf("unsafe identity advice %+v", r)
			}
			if mode == "rollback" && (r.DataQuality.ObservedStart <= epoch+300000 || !has(r.DataQuality, ReasonInsufficientHistory)) {
				t.Fatal("rollback pooled prior A")
			}
		})
	}
}
func TestObservedSegmentInference(t *testing.T) {
	in := fixture(600, 60)
	in.Containers[0].Identity.ReleaseStartedAt = 0
	out := run(t, in, shortPolicy())
	r := out.Results[1]
	if !r.Evidence.Identity.ReleaseStartInferred || !has(r.DataQuality, ReasonInferredReleaseStart) || len(r.Recommendations) == 0 {
		t.Fatalf("missing conservative segment inference %+v", r)
	}
}

func TestCurrentEvidenceMustBelongToSelectedRelease(t *testing.T) {
	for _, inferred := range []bool{false, true} {
		for _, field := range []string{"request", "limit", "inventory"} {
			for _, before := range []bool{false, true} {
				name := field
				if inferred {
					name += "/inferred"
				}
				if before {
					name += "/before"
				} else {
					name += "/at-boundary"
				}
				t.Run(name, func(t *testing.T) {
					in := fixture(1200, 60)
					c := &in.Containers[0]
					boundary := epoch + 600000
					c.Identity.ReleaseStartedAt = boundary
					if inferred {
						c.Identity.ReleaseStartedAt = 0
						c.CPU.Series = append(c.CPU.Series, Series{ID: "previous-release", WorkloadUID: "uid", Release: "B", Kind: SampleGauge, Samples: []Sample{{Timestamp: boundary - 1, Value: 10}}})
					}
					ts := boundary
					if before {
						ts--
					}
					reason := ReasonStaleInventory
					switch field {
					case "request":
						c.CPU.CurrentRequest.Timestamp = ts
						reason = ReasonStaleRequest
					case "limit":
						c.CPU.CurrentLimit.Timestamp = ts
						reason = ReasonStaleLimit
					case "inventory":
						c.Inventory.Timestamp = ts
					}
					p := shortPolicy()
					p.Evidence.FreshnessSeconds = 1200
					r := run(t, in, p).Results[1]
					if r.Evidence.Identity.ReleaseStartedAt != boundary {
						t.Fatalf("wrong selected release boundary: %+v", r.Evidence.Identity)
					}
					if !before {
						if has(r.DataQuality, reason) || len(r.Recommendations) != 2 {
							t.Fatalf("evidence at release boundary must remain valid: %+v", r)
						}
						return
					}
					if !has(r.DataQuality, reason) {
						t.Fatalf("pre-release evidence was accepted as fresh: %+v", r)
					}
					if field == "limit" {
						if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
							t.Fatalf("pre-release limit should block only limit advice: %+v", r)
						}
					} else if len(r.Recommendations) != 0 || r.NoActionReason != reason {
						t.Fatalf("pre-release evidence authorized downsizing: %+v", r)
					}
				})
			}
		}
	}
}

func TestCounterGapSurvivesDiscardedRate(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "internal", true: "terminal"}[terminal], func(t *testing.T) {
			in := fixture(1200, 60)
			s := &in.Containers[0].CPU.Series[0]
			s.Kind = SampleCPUCounterSeconds
			for i := range s.Samples {
				s.Samples[i].Value = float64(i) * .6
			}
			if terminal {
				s.Samples = append(s.Samples[:19], s.Samples[20]) // Last raw interval is 120 seconds.
			} else {
				s.Samples = append(s.Samples[:10], s.Samples[11:]...)
			}
			p := shortPolicy()
			p.Evidence.MaximumGapSeconds = 90
			p.Evidence.FreshnessSeconds = 300
			r := run(t, in, p).Results[1]
			if r.DataQuality.MaximumGapSeconds != 120 || r.DataQuality.GapCount != 1 || !has(r.DataQuality, ReasonInterruptedHistory) {
				t.Fatalf("discarded rate hid or duplicated the raw counter gap: %+v", r.DataQuality)
			}
			if len(r.Recommendations) != 0 || r.NoActionReason != ReasonInterruptedHistory || has(r.DataQuality, ReasonStaleUsage) || has(r.DataQuality, ReasonSparseCoverage) {
				t.Fatalf("raw counter gap must independently block otherwise fresh, covered usage: %+v", r)
			}
		})
	}
}

func TestReleaseGapAcrossPodLifetimesIsReported(t *testing.T) {
	in := fixture(660, 60)
	c := &in.Containers[0]
	first := c.CPU.Series[0]
	first.ID, first.PodUID = "old-pod", "old-pod"
	first.Samples = []Sample{{Timestamp: epoch, Value: 10}, {Timestamp: epoch + 60_000, Value: 10}}
	second := first
	second.ID, second.PodUID = "new-pod", "new-pod"
	second.Samples = []Sample{{Timestamp: epoch + 600_000, Value: 10}, {Timestamp: epoch + 660_000, Value: 10}}
	c.CPU.Series = []Series{first, second}
	c.Inventory.Eligible, c.Inventory.Observed = 2, 2

	p := shortPolicy()
	p.Evidence.MaximumGapSeconds = 300
	p.Evidence.FreshnessSeconds = 300
	r := run(t, in, p).Results[1]
	if r.DataQuality.MaximumGapSeconds != 540 || r.DataQuality.GapCount != 1 || !has(r.DataQuality, ReasonInterruptedHistory) {
		t.Fatalf("gap between pod lifetimes was not reported: %+v", r.DataQuality)
	}
}

func TestGaugeGapBeyondPolicyIsCountedAtRegularCadence(t *testing.T) {
	in := fixture(1200, 600)
	p := shortPolicy()
	p.Evidence.MaximumGapSeconds = 300
	r := run(t, in, p).Results[1]
	if r.DataQuality.MaximumGapSeconds != 600 || r.DataQuality.GapCount != 2 || !has(r.DataQuality, ReasonInterruptedHistory) {
		t.Fatalf("regular gauge gaps beyond policy were not counted: %+v", r.DataQuality)
	}
}

func TestSingleSamplePodChurnBelowGapPolicyIsNotCounted(t *testing.T) {
	in := fixture(120, 60)
	c := &in.Containers[0]
	base := c.CPU.Series[0]
	c.CPU.Series = nil
	for i, timestamp := range []int64{epoch, epoch + 60_000, epoch + 120_000} {
		series := base
		series.ID = fmt.Sprintf("pod-%d", i)
		series.PodUID = series.ID
		series.Samples = []Sample{{Timestamp: timestamp, Value: 10}}
		c.CPU.Series = append(c.CPU.Series, series)
	}
	c.Inventory.Eligible, c.Inventory.Observed = 3, 3
	p := shortPolicy()
	p.Evidence.MaximumGapSeconds = 300
	r := run(t, in, p).Results[1]
	if r.DataQuality.MaximumGapSeconds != 60 || r.DataQuality.GapCount != 0 || has(r.DataQuality, ReasonInterruptedHistory) {
		t.Fatalf("sub-policy churn gaps were counted without a known cadence: %+v", r.DataQuality)
	}
}

func TestAggregateTimestampTracksSelectedObservation(t *testing.T) {
	for _, kind := range []SampleKind{SampleGauge, SampleCPUCounterSeconds} {
		t.Run(string(kind), func(t *testing.T) {
			in := fixture(600, 60)
			c := &in.Containers[0]
			c.Memory.Series[0].Samples = append(c.Memory.Series[0].Samples, Sample{Timestamp: epoch + 233127, Value: 100 * 1024 * 1024})
			s := &c.CPU.Series[0]
			s.Kind = kind
			counter := 0.0
			for i := range s.Samples {
				value := float64(i)
				if kind == SampleCPUCounterSeconds {
					counter += value * .06
					value = counter
				}
				s.Samples[i].Value = value
			}
			p := shortPolicy()
			p.CPU.Percentile = 50
			out := run(t, in, p)
			for i, want := range []int64{epoch + 233127, epoch + 300000} {
				r := out.Results[i]
				if r.Evidence.AggregatedUsage.Timestamp != want || r.DataQuality.ObservedEnd != in.EvaluationTime {
					t.Fatalf("aggregate timestamp must identify its source independently of freshness: %+v", r)
				}
			}
		})
	}
}

func TestAggregateTimestampTiesAreDeterministic(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	first := &c.CPU.Series[0]
	first.ID = "a"
	first.Samples[2].Value = 100
	first.Samples[3].Value = 100
	second := *first
	second.ID, second.PodUID = "z", "second"
	second.Samples = append([]Sample(nil), first.Samples...)
	second.Samples[8].Value = 100
	second.Samples[9].Value = 100
	weak := second
	weak.ID, weak.PodUID = "weak", "third"
	weak.Samples = []Sample{{Timestamp: epoch + 540000, Value: 10}, {Timestamp: epoch + 600000, Value: 100}}
	c.CPU.Series = append(c.CPU.Series, second, weak)
	c.Inventory.Eligible, c.Inventory.Observed = 3, 3
	p := shortPolicy()
	p.CPU.Strategy = CPUStrategyMax
	out := run(t, in, p)
	usage := out.Results[1].Evidence.AggregatedUsage
	if usage.Value != 100 || usage.Timestamp != epoch+540000 {
		t.Fatalf("equal aggregates must use the strongest series and latest matching source sample: %+v", usage)
	}
	c.CPU.Series[0], c.CPU.Series[2] = c.CPU.Series[2], c.CPU.Series[0]
	for _, s := range c.CPU.Series {
		for i, j := 0, len(s.Samples)-1; i < j; i, j = i+1, j-1 {
			s.Samples[i], s.Samples[j] = s.Samples[j], s.Samples[i]
		}
	}
	if got := run(t, in, p); !reflect.DeepEqual(out, got) {
		t.Fatal("series or sample order changed tied aggregate provenance")
	}
}

func TestInventoryReasonOnlyForMaterialSuppressedDownsize(t *testing.T) {
	for _, current := range []float64{29, 31, 1000} {
		in := fixture(600, 60)
		c := &in.Containers[0]
		c.Inventory.Available = false
		c.CPU.CurrentRequest.Value = current // Suggested request is 30m.
		p := shortPolicy()
		p.CPU.RequestsOnly = true
		r := run(t, in, p).Results[1]
		want := ReasonNoMaterialChange
		if current == 1000 {
			want = ReasonUnknownInventory
		}
		if r.NoActionReason != want || len(r.Recommendations) != 0 || !has(r.DataQuality, ReasonUnknownInventory) {
			t.Fatalf("current %v: misleading inventory blocker: %+v", current, r)
		}
	}
}
func TestRequestsOnlyIgnoresLimitSizing(t *testing.T) {
	t.Run("unused limit overflow", func(t *testing.T) {
		in := fixture(600, 60)
		p := shortPolicy()
		p.CPU.RequestsOnly = true
		p.CPU.LimitsToRequestsRatio = math.MaxFloat64

		out, err := Analyze(in, p)
		if err != nil {
			t.Fatalf("request-only analysis failed on unused limit sizing: %v", err)
		}
		r := out.Results[1]
		if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
			t.Fatalf("request recommendation missing: %+v", r)
		}
		if has(r.DataQuality, ReasonBounds) {
			t.Fatalf("unused limit clamp degraded request-only quality: %+v", r.DataQuality)
		}
	})

	t.Run("request bound remains reported", func(t *testing.T) {
		in := fixture(600, 60)
		p := shortPolicy()
		p.CPU.RequestsOnly = true
		p.CPU.LimitsToRequestsRatio = math.MaxFloat64
		p.CPU.Bounds.Minimum = 50

		r := run(t, in, p).Results[1]
		if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests || r.Recommendations[0].SuggestedValue != 50 {
			t.Fatalf("bounded request recommendation missing: %+v", r)
		}
		if !has(r.DataQuality, ReasonBounds) {
			t.Fatalf("request bound was not reported: %+v", r.DataQuality)
		}
	})
}

func TestBoundBecomesNoActionReasonOnlyForMaterialSuppression(t *testing.T) {
	for _, test := range []struct {
		name           string
		currentRequest float64
		wantNoAction   Reason
	}{
		{"non-material candidate", 20, ReasonNoMaterialChange},
		{"material candidate", 69, ReasonBounds},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := fixture(600, 60)
			cpu := &in.Containers[0].CPU
			for i := range cpu.Series[0].Samples {
				cpu.Series[0].Samples[i].Value = 1
			}
			cpu.CurrentRequest.Value = test.currentRequest
			p := shortPolicy()
			p.CPU.RequestsOnly = true

			r := run(t, in, p).Results[1]
			if len(r.Recommendations) != 0 || r.NoActionReason != test.wantNoAction {
				t.Fatalf("wrong binding reason for current request %v: %+v", test.currentRequest, r)
			}
			if !has(r.DataQuality, ReasonBounds) {
				t.Fatalf("applied request bound was omitted from quality evidence: %+v", r.DataQuality)
			}
		})
	}
}

func TestStaleLimitClampCannotBecomeNoActionReason(t *testing.T) {
	in := fixture(600, 60)
	cpu := &in.Containers[0].CPU
	cpu.CurrentRequest.Value = 30
	cpu.CurrentLimit.Value = 64000
	cpu.CurrentLimit.Timestamp = epoch
	p := shortPolicy()
	p.CPU.LimitsToRequestsRatio = 3000

	r := run(t, in, p).Results[1]
	if len(r.Recommendations) != 0 || r.NoActionReason != ReasonNoMaterialChange {
		t.Fatalf("unusable limit clamp reported a binding bound: %+v", r)
	}
	if !has(r.DataQuality, ReasonStaleLimit) || !has(r.DataQuality, ReasonBounds) {
		t.Fatalf("stale bounded limit was omitted from quality evidence: %+v", r.DataQuality)
	}
}
func TestStaleGapsDuplicatesAndFreshSignals(t *testing.T) {
	for _, mode := range []string{"stale", "gap", "duplicates", "request", "limit"} {
		t.Run(mode, func(t *testing.T) {
			in := fixture(1200, 60)
			s := &in.Containers[0].CPU.Series[0]
			switch mode {
			case "stale":
				s.Samples = s.Samples[:5]
			case "gap":
				s.Samples = append(s.Samples[:5], s.Samples[15:]...)
			case "duplicates":
				s.Samples = []Sample{s.Samples[0], s.Samples[0], s.Samples[0], s.Samples[0]}
			case "request":
				in.Containers[0].CPU.CurrentRequest.Timestamp = epoch
			case "limit":
				in.Containers[0].CPU.CurrentLimit.Timestamp = epoch
			}
			r := run(t, in, shortPolicy()).Results[1]
			if mode == "limit" {
				if !has(r.DataQuality, ReasonStaleLimit) || len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
					t.Fatalf("stale limit handling %+v", r)
				}
			} else if len(r.Recommendations) > 0 || r.NoActionReason == "" {
				t.Fatalf("unsafe quality %+v", r)
			}
			if mode == "duplicates" && r.DataQuality.SampleCount != 1 {
				t.Fatal("duplicate/carried timestamp counted as new observation")
			}
			if mode == "gap" && (!has(r.DataQuality, ReasonInterruptedHistory) || r.DataQuality.GapCount == 0 || r.DataQuality.Coverage >= .9) {
				t.Fatalf("gap hidden: %+v", r.DataQuality)
			}
		})
	}
}
func TestInventoryCannotDisappear(t *testing.T) {
	for _, mode := range []string{"unknown", "excluded", "crashloop", "resource-missing", "stale"} {
		t.Run(mode, func(t *testing.T) {
			in := fixture(600, 60)
			c := &in.Containers[0]
			switch mode {
			case "unknown":
				c.Inventory = Inventory{}
			case "excluded":
				c.Inventory.Excluded = 3
			case "crashloop":
				c.Inventory.Eligible = 2
			case "resource-missing":
				c.Inventory.Eligible = 2
				c.Inventory.Observed = 2
			case "stale":
				c.Inventory.Timestamp = epoch
			}
			r := run(t, in, shortPolicy()).Results[1]
			if len(r.Recommendations) > 0 || r.NoActionReason == "" {
				t.Fatalf("unknown/excluded authorized downsize: %+v", r)
			}
			// Well-covered high usage may still justify growth, but quality stays partial.
			for i := range c.CPU.Series[0].Samples {
				c.CPU.Series[0].Samples[i].Value = 1000
			}
			r = run(t, in, shortPolicy()).Results[1]
			if len(r.Recommendations) == 0 || r.DataQuality.Status != DataQualityPartial {
				t.Fatalf("safe growth should retain uncertainty: %+v", r)
			}
		})
	}
}
func TestCounterNormalizationAndReplicaConservatism(t *testing.T) {
	gauge := fixture(600, 60)
	counter := fixture(600, 60)
	s := &counter.Containers[0].CPU.Series[0]
	s.Kind = SampleCPUCounterSeconds
	for i := range s.Samples {
		s.Samples[i].Value = float64(i) * .6
	}
	// Counter reset: at t=360, .6 seconds accrued after a restart.
	for i := 6; i < len(s.Samples); i++ {
		s.Samples[i].Value = float64(i-5) * .6
	}
	a, b := run(t, gauge, shortPolicy()).Results[1], run(t, counter, shortPolicy()).Results[1]
	if math.Abs(a.Evidence.AggregatedUsage.Value-b.Evidence.AggregatedUsage.Value) > 1e-10 || len(b.Recommendations) == 0 {
		t.Fatalf("counter/gauge differ: %+v %+v", a, b)
	}
	busy := gauge.Containers[0].CPU.Series[0]
	busy.ID = "busy"
	busy.PodUID = "busy"
	busy.Samples = append([]Sample(nil), busy.Samples...)
	for i := range busy.Samples {
		busy.Samples[i].Value = 200
	}
	gauge.Containers[0].CPU.Series = append(gauge.Containers[0].CPU.Series, busy)
	gauge.Containers[0].Inventory.Eligible = 2
	gauge.Containers[0].Inventory.Observed = 2
	if r := run(t, gauge, shortPolicy()).Results[1]; r.Evidence.AggregatedUsage.Value != 200 {
		t.Fatalf("busy replica diluted %+v", r)
	}
}
func TestZeroMissingBoundsAndIndependentSettings(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	for i := range c.CPU.Series[0].Samples {
		c.CPU.Series[0].Samples[i].Value = 0
	}
	r := run(t, in, shortPolicy()).Results[1]
	if !r.Evidence.AggregatedUsage.Available || r.Evidence.AggregatedUsage.Value != 0 || r.Recommendations[0].SuggestedValue != 20 {
		t.Fatalf("zero is not observed idle %+v", r)
	}
	c.CPU.Series = nil
	r = run(t, in, shortPolicy()).Results[1]
	if r.Evidence.AggregatedUsage.Available || r.NoActionReason != ReasonMissingUsage {
		t.Fatalf("missing converted to idle %+v", r)
	}
	in = fixture(600, 60)
	in.Containers[0].CPU.CurrentRequest.Value = 30
	in.Containers[0].CPU.CurrentLimit.Value = 500
	r = run(t, in, shortPolicy()).Results[1]
	if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingLimits {
		t.Fatalf("limit change wrongly coupled to request delta %+v", r)
	}
	p := shortPolicy()
	p.CPU.Bounds.Maximum = 100
	in.Containers[0].CPU.Series[0].Samples[0].Value = 10000
	p.CPU.Strategy = CPUStrategyMax
	r = run(t, in, p).Results[1]
	for _, rec := range r.Recommendations {
		if rec.SuggestedValue > 100 {
			t.Fatal("bound exceeded")
		}
	}
}
func TestDeterminismAndValidation(t *testing.T) {
	in := fixture(600, 60)
	before, _ := json.Marshal(in)
	out := run(t, in, shortPolicy())
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
	for _, r := range []*ResourceObservation{&in.Containers[0].CPU, &in.Containers[0].Memory} {
		s := r.Series[0].Samples
		for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
			s[i], s[j] = s[j], s[i]
		}
	}
	if got := run(t, in, shortPolicy()); !reflect.DeepEqual(out, got) {
		t.Fatal("sample order affects output")
	}
	in.SchemaVersion = "resource-analysis-input/v1"
	if _, err := Analyze(in, Policy{}); err == nil || !strings.Contains(err.Error(), "unsupported input schema") {
		t.Fatal("v1 was accepted")
	}
	if _, err := NormalizePolicy(Policy{CPU: CPUPolicy{Bounds: Bounds{Minimum: 100, Maximum: 50}}}); err == nil {
		t.Fatal("invalid bounds accepted")
	}
	in = fixture(600, 60)
	in.Containers[0].CPU.Series[0].Samples[0].Value = math.NaN()
	if _, err := Analyze(in, shortPolicy()); err == nil {
		t.Fatal("NaN accepted")
	}
}

func TestGoldenNormalizedSnapshot(t *testing.T) {
	b, err := os.ReadFile("testdata/default-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var in Input
	if err = json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	p := shortPolicy()
	p.CPU.Percentile = 50
	out := run(t, in, p)
	b, err = os.ReadFile("testdata/default-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var want Output
	if err = json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("golden output mismatch: %+v", out)
	}
}
func TestUnknownSeriesAndLimitSafety(t *testing.T) {
	in := fixture(600, 60)
	unknown := in.Containers[0].CPU.Series[0]
	unknown.ID = "unidentified"
	unknown.Release = ""
	in.Containers[0].CPU.Series = append(in.Containers[0].CPU.Series, unknown)
	r := run(t, in, shortPolicy()).Results[1]
	if !has(r.DataQuality, ReasonUnknownSeriesIdentity) || len(r.Recommendations) > 0 {
		t.Fatal("unknown series hidden")
	}
	in = fixture(600, 60)
	in.Containers[0].CPU.CurrentLimit.Value = 0
	in.Containers[0].Inventory.Available = false
	r = run(t, in, shortPolicy()).Results[1]
	if len(r.Recommendations) > 0 {
		t.Fatal("unknown inventory tightened unlimited resource")
	}
	in = fixture(600, 60)
	in.Containers[0].CPU.CurrentRequest.Value = 120
	p := shortPolicy()
	p.CPU.Bounds.Minimum = 100
	p.CPU.Bounds.Maximum = 100
	r = run(t, in, p).Results[1]
	for _, rec := range r.Recommendations {
		if rec.Setting == SettingLimits && rec.SuggestedValue < 120 {
			t.Fatal("limit fell below retained request")
		}
	}
}

func TestStableReleaseSurvivesReplicaChurn(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "scale out", true: "replacement"}[replacement], func(t *testing.T) {
			in := fixture(7*86400, 60)
			c := &in.Containers[0]
			for _, obs := range []*ResourceObservation{&c.CPU, &c.Memory} {
				recent := obs.Series[0]
				recent.ID = "new-pod"
				recent.PodUID = "new-pod"
				recent.Samples = append([]Sample(nil), recent.Samples[len(recent.Samples)-31:]...)
				if replacement {
					obs.Series[0].Samples = obs.Series[0].Samples[:len(obs.Series[0].Samples)-30]
				}
				obs.Series = append(obs.Series, recent)
			}
			if !replacement {
				c.Inventory.Eligible = 2
				c.Inventory.Observed = 2
			}
			out := run(t, in, Policy{})
			for _, r := range out.Results {
				expectedConfidence := 95
				if replacement {
					expectedConfidence = 94
				} // The supporting old pod ran 30 minutes short of a full week.
				if len(r.Recommendations) == 0 || r.Recommendations[0].Confidence != expectedConfidence || r.DataQuality.Coverage != 1 {
					t.Fatalf("healthy churn erased release history: %+v", r)
				}
			}
			for i := range c.CPU.Series[1].Samples {
				c.CPU.Series[1].Samples[i].Value = 1000
			}
			c.Inventory.Available = false
			r := run(t, in, Policy{}).Results[1]
			if len(r.Recommendations) == 0 || r.Recommendations[0].SuggestedValue != 3000 || r.Recommendations[0].Confidence >= 95 {
				t.Fatalf("new replica peak cannot grow stable release %+v", r)
			}
		})
	}
}

func TestReleaseCoverageIndependentOfOlderLookback(t *testing.T) {
	for _, inferred := range []bool{false, true} {
		t.Run(map[bool]string{false: "activation boundary", true: "observed boundary"}[inferred], func(t *testing.T) {
			in := fixture(7*86400, 60)
			if inferred {
				in.Containers[0].Identity.ReleaseStartedAt = 0
			}
			weekly := run(t, in, Policy{})
			in.WindowStart -= 23 * 86400 * 1000
			longer := run(t, in, Policy{})
			if !reflect.DeepEqual(weekly, longer) {
				t.Fatalf("older lookback changed identical current-release evidence: weekly=%+v longer=%+v", weekly.Results, longer.Results)
			}
			for _, r := range longer.Results {
				if r.DataQuality.Coverage != 1 || len(r.Recommendations) == 0 {
					t.Fatalf("dense week diluted by pre-release time: %+v", r)
				}
			}
		})
	}
}

func TestSinglePointInferredReleaseHasFiniteCoverage(t *testing.T) {
	in := fixture(600, 60)
	c := &in.Containers[0]
	c.Identity.ReleaseStartedAt = 0
	for _, obs := range []*ResourceObservation{&c.CPU, &c.Memory} {
		obs.Series[0].Samples = obs.Series[0].Samples[len(obs.Series[0].Samples)-1:]
	}
	out := run(t, in, Policy{})
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("zero-length release segment cannot be serialized: %v", err)
	}
	for _, r := range out.Results {
		if r.DataQuality.Coverage != 0 || len(r.Recommendations) != 0 {
			t.Fatalf("single-point release authorized sizing: %+v", r)
		}
	}
}
