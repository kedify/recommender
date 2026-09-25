// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"encoding/json"
	"testing"
)

func unsetFixture(resource Resource) (Input, Policy, int, float64) {
	in, p := fixture(600, 60), shortPolicy()
	index, candidate := 1, float64(24)
	obs := &in.Containers[0].CPU
	p.CPU.HeadroomCoefficient, p.CPU.LimitsToRequestsRatio = 1, 1
	if resource == ResourceMemory {
		index, candidate = 0, 2*1024*1024
		obs = &in.Containers[0].Memory
		p.Memory.HeadroomCoefficient, p.Memory.LimitsToRequestsRatio = 1, 1
		p.Memory.Bounds.Minimum = 1024 * 1024
	}
	for i := range obs.Series[0].Samples {
		obs.Series[0].Samples[i].Value = candidate
	}
	obs.CurrentRequest = Signal{Available: true, Unset: true, Timestamp: in.EvaluationTime}
	obs.CurrentLimit = obs.CurrentRequest
	return in, p, index, candidate
}

func TestUnsetSettingsBypassMinimumChange(t *testing.T) {
	for _, resource := range []Resource{ResourceCPU, ResourceMemory} {
		t.Run(string(resource), func(t *testing.T) {
			in, p, index, candidate := unsetFixture(resource)
			// Exercise the public JSON boundary, preserving known absence.
			data, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Input
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			r := run(t, decoded, p).Results[index]
			if len(r.Recommendations) != 2 || !r.Evidence.CurrentRequest.Unset || !r.Evidence.CurrentLimit.Unset {
				t.Fatalf("unset settings were not initialized: %+v", r)
			}
			for _, rec := range r.Recommendations {
				if rec.SuggestedValue != candidate || !rec.CurrentUnset {
					t.Fatalf("incorrect initialization: %+v", rec)
				}
			}
			for _, trace := range r.DecisionTrace.Settings {
				initialized := false
				for _, step := range trace.Steps {
					if step.Rule == "material change" {
						t.Fatal("unset setting was compared with numeric zero")
					}
					initialized = initialized || step.Rule == "initialize unset setting"
				}
				if !initialized || trace.Disposition != "recommended" {
					t.Fatalf("missing initialization trace: %+v", trace)
				}
			}
		})
	}
}

func TestNumericSettingsKeepMinimumChange(t *testing.T) {
	for _, resource := range []Resource{ResourceCPU, ResourceMemory} {
		for _, existing := range []float64{0, 1} {
			in, p, index, candidate := unsetFixture(resource)
			obs := &in.Containers[0].CPU
			if resource == ResourceMemory {
				obs = &in.Containers[0].Memory
			}
			obs.CurrentRequest.Unset, obs.CurrentLimit.Unset = false, false
			obs.CurrentRequest.Value, obs.CurrentLimit.Value = existing*candidate/2, existing*candidate/2
			r := run(t, in, p).Results[index]
			if len(r.Recommendations) != 0 || r.NoActionReason != ReasonNoMaterialChange {
				t.Fatalf("%s numeric setting bypassed thresholds: %+v", resource, r)
			}
		}
	}
}

func TestUnsetSettingsPreserveGuards(t *testing.T) {
	for _, resource := range []Resource{ResourceCPU, ResourceMemory} {
		for _, tc := range []struct {
			name   string
			change func(*Input, *ResourceObservation, *Policy)
			want   []Setting
			reason Reason
		}{
			{"unknown request", func(_ *Input, o *ResourceObservation, _ *Policy) { o.CurrentRequest = Signal{} }, nil, ReasonMissingRequest},
			{"stale unset request", func(_ *Input, o *ResourceObservation, _ *Policy) { o.CurrentRequest.Timestamp = epoch }, nil, ReasonStaleRequest},
			{"unknown limit", func(_ *Input, o *ResourceObservation, _ *Policy) { o.CurrentLimit = Signal{} }, []Setting{SettingRequests}, ""},
			{"stale unset limit", func(_ *Input, o *ResourceObservation, _ *Policy) { o.CurrentLimit.Timestamp = epoch }, []Setting{SettingRequests}, ""},
			{"missing usage", func(_ *Input, o *ResourceObservation, _ *Policy) { o.Series = nil }, nil, ReasonMissingUsage},
			{"short history", func(_ *Input, _ *ResourceObservation, p *Policy) { p.Evidence.MinimumHistorySeconds = 1200 }, nil, ReasonInsufficientHistory},
			{"missing inventory", func(in *Input, _ *ResourceObservation, _ *Policy) { in.Containers[0].Inventory.Available = false }, []Setting{SettingRequests}, ""},
			{"requests only", func(_ *Input, _ *ResourceObservation, p *Policy) {
				p.CPU.RequestsOnly, p.Memory.RequestsOnly = true, true
			}, []Setting{SettingRequests}, ""},
			{"retained lower limit", func(in *Input, o *ResourceObservation, p *Policy) {
				o.CurrentLimit = Signal{Available: true, Timestamp: in.EvaluationTime, Value: o.Series[0].Samples[0].Value / 2}
				p.CPU.RequestsOnly, p.Memory.RequestsOnly = true, true
			}, nil, ReasonBounds},
			{"limit below retained request", func(_ *Input, o *ResourceObservation, _ *Policy) {
				o.CurrentRequest.Unset = false
				o.CurrentRequest.Value = o.Series[0].Samples[0].Value + 1
			}, nil, ReasonBounds},
		} {
			t.Run(string(resource)+"/"+tc.name, func(t *testing.T) {
				in, p, index, _ := unsetFixture(resource)
				obs := &in.Containers[0].CPU
				if resource == ResourceMemory {
					obs = &in.Containers[0].Memory
				}
				tc.change(&in, obs, &p)
				r := run(t, in, p).Results[index]
				if len(r.Recommendations) != len(tc.want) {
					t.Fatalf("guard not preserved: %+v", r)
				}
				for i, setting := range tc.want {
					if r.Recommendations[i].Setting != setting {
						t.Fatalf("wrong setting initialized: %+v", r)
					}
				}
				if tc.reason != "" && r.NoActionReason != tc.reason {
					t.Fatalf("no-action reason = %s, want %s", r.NoActionReason, tc.reason)
				}
			})
		}
	}
}

func TestUnsetMemoryLimitPreservesOOMGuard(t *testing.T) {
	in, p, index, _ := unsetFixture(ResourceMemory)
	in.Containers[0].OOMKills = []OOMKill{oomKill("unknown-limit", epoch+60000, 0)}
	r := run(t, in, p).Results[index]
	if len(r.Recommendations) != 1 || r.Recommendations[0].Setting != SettingRequests {
		t.Fatalf("unsafe unset memory limit initialized after OOM: %+v", r)
	}
	trace := r.DecisionTrace.Settings[1]
	if trace.Disposition != "retained" || len(trace.Reasons) != 1 || trace.Reasons[0] != ReasonOOMLimitUnknown {
		t.Fatalf("missing OOM guard trace: %+v", trace)
	}
}

func TestUnsetSignalRejectsNumericValue(t *testing.T) {
	for _, limit := range []bool{false, true} {
		in, p, _, _ := unsetFixture(ResourceCPU)
		signal := &in.Containers[0].CPU.CurrentRequest
		if limit {
			signal = &in.Containers[0].CPU.CurrentLimit
		}
		signal.Value = 1
		if _, err := Analyze(in, p); err == nil {
			t.Fatal("contradictory unset and numeric allocation accepted")
		}
	}
}
