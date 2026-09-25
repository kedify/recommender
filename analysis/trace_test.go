// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"reflect"
	"testing"
)

func TestDecisionTraceCurrentSettingReasons(t *testing.T) {
	for _, tt := range []struct {
		name      string
		setting   Setting
		available bool
		reason    Reason
	}{
		{"missing request", SettingRequests, false, ReasonMissingRequest},
		{"stale request", SettingRequests, true, ReasonStaleRequest},
		{"missing limit", SettingLimits, false, ReasonMissingLimit},
		{"stale limit", SettingLimits, true, ReasonStaleLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := fixture(600, 60)
			for _, obs := range []*ResourceObservation{&in.Containers[0].CPU, &in.Containers[0].Memory} {
				signal := &obs.CurrentRequest
				if tt.setting == SettingLimits {
					signal = &obs.CurrentLimit
				}
				signal.Available, signal.Timestamp = tt.available, epoch
			}
			for _, result := range run(t, in, shortPolicy()).Results {
				for _, trace := range result.DecisionTrace.Settings {
					if trace.Setting == tt.setting && (trace.Disposition != "unavailable" || !reflect.DeepEqual(trace.Reasons, []Reason{tt.reason})) {
						t.Fatalf("%s %s trace: %+v", result.Resource, tt.setting, trace)
					}
				}
			}
		})
	}
}

func TestDecisionTraceDispositions(t *testing.T) {
	for _, tt := range []struct {
		name     string
		change   func(*Input, *Policy)
		expected string
		setting  int
	}{
		{"recommended", func(*Input, *Policy) {}, "recommended", 0},
		{"request-only limit", func(_ *Input, p *Policy) { p.CPU.RequestsOnly = true }, "disabled", 1},
		{"missing usage", func(in *Input, _ *Policy) { in.Containers[0].CPU.Series = nil }, "unavailable", 0},
		{"no material change", func(in *Input, _ *Policy) { in.Containers[0].CPU.CurrentRequest.Value = 30 }, "retained", 0},
		{"inventory guard", func(in *Input, _ *Policy) { in.Containers[0].Inventory.Available = false }, "retained", 0},
		{"missing limit", func(in *Input, _ *Policy) { in.Containers[0].CPU.CurrentLimit.Available = false }, "unavailable", 1},
		{"bounds", func(in *Input, p *Policy) { p.CPU.RequestsOnly = true; in.Containers[0].CPU.CurrentLimit.Value = 20 }, "retained", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, p := fixture(600, 60), shortPolicy()
			tt.change(&in, &p)
			out := run(t, in, p)
			trace := out.Results[1].DecisionTrace
			if trace == nil || len(trace.Settings) != 2 || trace.Settings[tt.setting].Disposition != tt.expected {
				t.Fatalf("trace: %+v", trace)
			}
			if tt.name == "recommended" && (trace.Source.SeriesID != "pod-1" || trace.Source.Timestamp == 0 || len(trace.Settings[0].Steps) < 3) {
				t.Fatalf("missing calculation/source: %+v", trace)
			}
		})
	}
}
func TestSharedSampleNormalization(t *testing.T) {
	values, err := NormalizeSamples(Series{Kind: SampleCPUCounterSeconds, Samples: []Sample{{Timestamp: 3000, Value: 1}, {Timestamp: 1000, Value: 10}, {Timestamp: 2000, Value: 12}, {Timestamp: 2000, Value: 12}}}, 1000, 3000)
	if err != nil || len(values) != 2 || values[0].Value != 2000 || values[1].Value != 1000 {
		t.Fatalf("counter/reset normalization: %v %v", values, err)
	}
}

func TestTraceExplainsFallbackRejections(t *testing.T) {
	in := fallbackFixture()
	in.Containers[0].PreviousReleases = []PreviousRelease{previousFixture("too-short", epoch-60000, 300, 30), previousFixture("selected", epoch-4*3600000, 3600, 30)}
	out := run(t, in, Policy{})
	for _, r := range out.Results {
		trace := r.DecisionTrace
		if trace.Source.Release != "selected" || len(trace.Fallbacks) != 2 || trace.Fallbacks[0].Selected || len(trace.Fallbacks[0].Reasons) == 0 || !trace.Fallbacks[1].Selected {
			t.Fatalf("trace lost fallback reasoning: %+v", trace)
		}
	}
}
