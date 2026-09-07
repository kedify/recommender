package analysis

import (
	"encoding/json"
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
	if isMaterialChange(100, 109, 8) {
		t.Fatal("a change below ten percent must be ignored")
	}
	if !isMaterialChange(100, 111, minimumMemoryAbsChange) {
		t.Fatal("the current detector's literal memory threshold of 8 must be preserved")
	}
	if isMaterialChange(100, 140, minimumCPUAbsoluteChange) {
		t.Fatal("a CPU change below 50 millicores must be ignored")
	}
	if !isMaterialChange(100, 150, minimumCPUAbsoluteChange) {
		t.Fatal("a CPU change of 50 millicores must be included")
	}
}

func TestMissingSignalsAreTypedAndDoNotBecomeZeroRecommendations(t *testing.T) {
	input := Input{
		SchemaVersion:         InputSchemaVersion,
		ObservedIntervalHours: 24,
		Containers: []ContainerObservation{{
			Target: Target{Namespace: "shop", Kind: "DaemonSet", Name: "collector", Container: "collector"},
			CPU: ResourceObservation{
				CurrentLimit: available(500),
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
	if cpu.DataQuality.Status != DataQualityUnavailable || !reflect.DeepEqual(cpu.DataQuality.MissingSignals, []SignalName{SignalAggregatedUsage, SignalCurrentRequest}) {
		t.Fatalf("unexpected CPU quality: %#v", cpu.DataQuality)
	}
	if len(cpu.Recommendations) != 0 {
		t.Fatalf("missing usage emitted numeric recommendations: %#v", cpu.Recommendations)
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
