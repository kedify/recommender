// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
)

func TestGoldenDefaultPolicy(t *testing.T) {
	inputBytes, err := os.ReadFile("testdata/default-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var decoded Input
	if err := json.Unmarshal(inputBytes, &decoded); err != nil {
		t.Fatal(err)
	}

	programmatic := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 168,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "Deployment", Name: "checkout", Container: "app"},
			Memory: ResourceObservation{
				AggregatedUsage: available(25 * 1024 * 1024),
				CurrentRequest:  available(64 * 1024 * 1024),
				CurrentLimit:    available(128 * 1024 * 1024),
			},
			CPU: ResourceObservation{
				AggregatedUsage: available(40),
				CurrentRequest:  available(250),
				CurrentLimit:    available(1000),
			},
		}},
	}
	if !reflect.DeepEqual(decoded, programmatic) {
		t.Fatalf("decoded fixture differs from programmatic input\ndecoded: %#v\nprogrammatic: %#v", decoded, programmatic)
	}

	got, err := Analyze(decoded, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	gotAgain, err := Analyze(programmatic, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, gotAgain) {
		t.Fatal("same normalized snapshot and policy produced different output")
	}

	wantBytes, err := os.ReadFile("testdata/default-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var want Output
	if err := json.Unmarshal(wantBytes, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("golden output mismatch\ngot:\n%s", gotJSON)
	}
}

func TestPolicyVersionMatchesDashboardIdentity(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   string
	}{
		{
			name: "defaults",
			want: "cpu=p95,h=3,r=5;mem=max,h=1.2,r=3",
		},
		{
			name: "custom max",
			policy: Policy{
				CPU:    CPUPolicy{Strategy: CPUStrategyMax, HeadroomCoefficient: 2.5, LimitsToRequestsRatio: 4},
				Memory: MemoryPolicy{Strategy: MemoryStrategyMax, HeadroomCoefficient: 1.4, LimitsToRequestsRatio: 2},
			},
			want: "cpu=max,h=2.5,r=4;mem=max,h=1.4,r=2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := PolicyVersion(test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("PolicyVersion() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNormalizePolicyRejectsLimitRatiosBelowOne(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   string
	}{
		{
			name:   "CPU",
			policy: Policy{CPU: CPUPolicy{LimitsToRequestsRatio: 0.9}},
			want:   "cpu.limitsToRequestsRatio must be greater than or equal to 1",
		},
		{
			name:   "memory",
			policy: Policy{Memory: MemoryPolicy{LimitsToRequestsRatio: 0.9}},
			want:   "memory.limitsToRequestsRatio must be greater than or equal to 1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicy(test.policy)
			if err == nil || err.Error() != test.want {
				t.Fatalf("NormalizePolicy() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCustomPolicy(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 24,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "StatefulSet", Name: "worker", Container: "worker"},
			CPU: ResourceObservation{
				AggregatedUsage: available(50),
				CurrentRequest:  available(200),
				CurrentLimit:    available(500),
			},
			Memory: ResourceObservation{
				AggregatedUsage: available(20 * 1024 * 1024),
				CurrentRequest:  available(64 * 1024 * 1024),
				CurrentLimit:    available(100 * 1024 * 1024),
			},
		}},
	}
	policy := Policy{
		CPU:    CPUPolicy{Strategy: CPUStrategyMax, HeadroomCoefficient: 2, LimitsToRequestsRatio: 4},
		Memory: MemoryPolicy{Strategy: MemoryStrategyMax, HeadroomCoefficient: 1.5, LimitsToRequestsRatio: 2},
	}

	got, err := Analyze(input, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.EffectivePolicy.CPU.Strategy != CPUStrategyMax || got.EffectivePolicy.CPU.Percentile != 0 {
		t.Fatalf("unexpected effective CPU strategy: %#v", got.EffectivePolicy.CPU)
	}
	assertRecommendation(t, got.Results[0], SettingRequests, 64*1024*1024, 30*1024*1024)
	assertRecommendation(t, got.Results[0], SettingLimits, 100*1024*1024, 60*1024*1024)
	assertRecommendation(t, got.Results[1], SettingRequests, 200, 100)
	assertRecommendation(t, got.Results[1], SettingLimits, 500, 400)
}

func TestMinimumValues(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 1,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "Deployment", Name: "idle", Container: "idle"},
			CPU: ResourceObservation{
				AggregatedUsage: available(1),
				CurrentRequest:  available(100),
				CurrentLimit:    available(200),
			},
			Memory: ResourceObservation{
				AggregatedUsage: available(1),
				CurrentRequest:  available(20 * 1024 * 1024),
				CurrentLimit:    available(40 * 1024 * 1024),
			},
		}},
	}

	got, err := Analyze(input, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	assertRecommendation(t, got.Results[0], SettingRequests, 20*1024*1024, minimumMemoryBytes)
	assertRecommendation(t, got.Results[1], SettingRequests, 100, minimumCPUMillicores)
}

func TestChangeThresholdsMatchCurrentDetector(t *testing.T) {
	fixture, err := os.ReadFile("testdata/legacy-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []struct {
		Name                  string  `json:"name"`
		Current               float64 `json:"current"`
		Suggested             float64 `json:"suggested"`
		MinimumAbsoluteChange float64 `json:"minimumAbsoluteChange"`
		Want                  bool    `json:"recommend"`
	}
	if err := json.Unmarshal(fixture, &tests); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if got := isMaterialChange(test.Current, test.Suggested, test.MinimumAbsoluteChange); got != test.Want {
				t.Fatalf("isMaterialChange(%v, %v, %v) = %t, want %t", test.Current, test.Suggested, test.MinimumAbsoluteChange, got, test.Want)
			}
		})
	}
}

func TestConfidenceMatchesCurrentDetector(t *testing.T) {
	tests := []struct {
		hours int
		want  int
	}{
		{hours: 1, want: 20},
		{hours: 100, want: 56},
		{hours: 168, want: 95},
		{hours: 200, want: 113},
	}
	for _, test := range tests {
		if got := recommendationConfidence(test.hours); got != test.want {
			t.Errorf("recommendationConfidence(%d) = %d, want %d", test.hours, got, test.want)
		}
	}
}

func TestMissingSignalsAreTypedAndDoNotBecomeZeroRecommendations(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 24,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "DaemonSet", Name: "collector", Container: "collector"},
			CPU: ResourceObservation{
				CurrentLimit: Signal{},
			},
			Memory: ResourceObservation{
				AggregatedUsage: available(20 * 1024 * 1024),
				CurrentRequest:  available(64 * 1024 * 1024),
			},
		}},
	}

	got, err := Analyze(input, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	memory, cpu := got.Results[0], got.Results[1]
	if memory.DataQuality.Status != DataQualityPartial || !reflect.DeepEqual(memory.DataQuality.MissingSignals, []SignalName{SignalCurrentLimit}) {
		t.Fatalf("unexpected memory quality: %#v", memory.DataQuality)
	}
	if len(memory.Recommendations) != 1 || memory.Recommendations[0].Setting != SettingRequests {
		t.Fatalf("missing current limit must only allow a request recommendation: %#v", memory.Recommendations)
	}
	if cpu.DataQuality.Status != DataQualityUnavailable || !reflect.DeepEqual(cpu.DataQuality.MissingSignals, []SignalName{SignalAggregatedUsage, SignalCurrentRequest, SignalCurrentLimit}) {
		t.Fatalf("unexpected CPU quality: %#v", cpu.DataQuality)
	}
	if len(cpu.Recommendations) != 0 {
		t.Fatalf("missing usage emitted numeric recommendations: %#v", cpu.Recommendations)
	}
}

func TestMissingLimitIsPartialWhenRequestChangeIsMinor(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 24,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "Deployment", Name: "api", Container: "api"},
			CPU: ResourceObservation{
				AggregatedUsage: available(100),
				CurrentRequest:  available(300),
			},
			Memory: ResourceObservation{
				AggregatedUsage: available(20 * 1024 * 1024),
				CurrentRequest:  available(24 * 1024 * 1024),
			},
		}},
	}

	got, err := Analyze(input, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range got.Results {
		if result.DataQuality.Status != DataQualityPartial || !reflect.DeepEqual(result.DataQuality.MissingSignals, []SignalName{SignalCurrentLimit}) {
			t.Fatalf("unexpected quality for %s: %#v", result.Resource, result.DataQuality)
		}
		if len(result.Recommendations) != 0 {
			t.Fatalf("expected minor %s request change to emit no recommendation: %#v", result.Resource, result.Recommendations)
		}
	}
}

func TestInputOrderDoesNotAffectOutputOrMutateInput(t *testing.T) {
	first := missingObservation("zeta")
	second := missingObservation("alpha")
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 1,
		Containers:            []ContainerObservation{first, second},
	}
	reversed := input
	reversed.Containers = []ContainerObservation{second, first}

	got, err := Analyze(input, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	gotReversed, err := Analyze(reversed, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, gotReversed) {
		t.Fatalf("input order changed output\nfirst: %#v\nreversed: %#v", got, gotReversed)
	}
	if input.Containers[0].Target.Name != "zeta" {
		t.Fatalf("Analyze mutated caller input: %#v", input.Containers)
	}
}

func TestUnavailableSignalsAreCanonicalizedWithoutMutatingInput(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 1,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "Deployment", Name: "api", Container: "api"},
			CPU: ResourceObservation{
				AggregatedUsage: Signal{Value: math.NaN()},
				CurrentRequest:  Signal{Value: math.Inf(1)},
				CurrentLimit:    Signal{Value: -1},
			},
		}},
	}

	got, err := Analyze(input, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !math.IsNaN(input.Containers[0].CPU.AggregatedUsage.Value) {
		t.Fatal("Analyze mutated the caller's unavailable signal")
	}
	cpu := got.Results[1]
	if cpu.Evidence.AggregatedUsage.Value != 0 || cpu.Evidence.CurrentRequest.Value != 0 || cpu.Evidence.CurrentLimit.Value != 0 {
		t.Fatalf("unavailable signals are not canonical: %#v", cpu.Evidence)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}
}

func TestAnalyzeRejectsArithmeticOverflow(t *testing.T) {
	tests := []struct {
		name   string
		cpu    ResourceObservation
		policy Policy
		want   string
	}{
		{
			name: "request",
			cpu: ResourceObservation{
				AggregatedUsage: available(math.MaxFloat64),
				CurrentRequest:  available(100),
				CurrentLimit:    available(1000),
			},
			policy: Policy{CPU: CPUPolicy{HeadroomCoefficient: 2, LimitsToRequestsRatio: 1}},
			want:   "containers[0]: cpu suggested request is not finite",
		},
		{
			name: "limit",
			cpu: ResourceObservation{
				AggregatedUsage: available(math.MaxFloat64 / 4),
				CurrentRequest:  available(math.MaxFloat64),
				CurrentLimit:    available(math.MaxFloat64),
			},
			policy: Policy{CPU: CPUPolicy{HeadroomCoefficient: 2, LimitsToRequestsRatio: 3}},
			want:   "containers[0]: cpu suggested limit is not finite",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := Input{
				SchemaVersion:         InputSchemaVersion,
				ObservedIntervalHours: 1,
				Containers: []ContainerObservation{{
					Target: Target{Namespace: "shop", Kind: "Deployment", Name: "api", Container: "api"},
					CPU:    test.cpu,
				}},
			}
			got, err := Analyze(input, test.policy)
			if err == nil || err.Error() != test.want {
				t.Fatalf("Analyze() error = %v, want %q", err, test.want)
			}
			if !reflect.DeepEqual(got, Output{}) {
				t.Fatalf("Analyze() returned partial output on overflow: %#v", got)
			}
		})
	}
}

func TestAnalyzeErrorsUseOriginalContainerIndex(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 1,
		Containers: []ContainerObservation{
			{
				Target: Target{Namespace: "z-last", Kind: "Deployment", Name: "api"},
			},
			missingObservation("valid"),
		},
	}

	_, err := Analyze(input, Policy{})
	want := "containers[0]: target namespace, kind, name, and container are required"
	if err == nil || err.Error() != want {
		t.Fatalf("Analyze() error = %v, want %q", err, want)
	}
}

func TestRejectsInvalidInputAndPolicy(t *testing.T) {
	valid := Input{SchemaVersion: InputSchemaVersion, ObservedIntervalHours: 1}

	invalidVersion := valid
	invalidVersion.SchemaVersion = "v2"
	if _, err := Analyze(invalidVersion, Policy{}); err == nil {
		t.Fatal("expected unsupported schema version error")
	}
	if _, err := Analyze(valid, Policy{CPU: CPUPolicy{Strategy: CPUStrategyPercentile, Percentile: 100}}); err == nil {
		t.Fatal("expected invalid CPU percentile error")
	}
}

func available(value float64) Signal {
	return Signal{Available: true, Value: value}
}

func missingObservation(name string) ContainerObservation {
	return ContainerObservation{
		Target: Target{Namespace: "shop", Kind: "Deployment", Name: name, Container: "app"},
	}
}

func assertRecommendation(t *testing.T, result ResourceAnalysis, setting Setting, current, suggested float64) {
	t.Helper()
	for _, recommendation := range result.Recommendations {
		if recommendation.Setting == setting {
			if recommendation.CurrentValue != current || recommendation.SuggestedValue != suggested {
				t.Fatalf("unexpected %s recommendation: %#v", setting, recommendation)
			}
			return
		}
	}
	t.Fatalf("missing %s recommendation in %#v", setting, result.Recommendations)
}
