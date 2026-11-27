// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package reviewpatch

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/kedify/recommender/analysis"
)

const mi = 1024 * 1024

// Mirrors the AKS regression using synthetic identity and the observed quantities.
func oomResult() (analysis.Target, *analysis.Output) {
	target := analysis.Target{Namespace: "default", Kind: "Deployment", Name: "oom-example", Container: "app", WorkloadUID: "synthetic-uid", Release: "pod-template-hash:example"}
	evidence := analysis.ResourceEvidence{
		Identity:       analysis.CurrentIdentity{Available: true, WorkloadUID: target.WorkloadUID, Release: target.Release},
		CurrentRequest: analysis.Signal{Available: true, Value: 8 * mi},
		CurrentLimit:   analysis.Signal{Available: true, Value: 64 * mi},
	}
	return target, &analysis.Output{
		SchemaVersion: analysis.OutputSchemaVersion, PolicyVersion: "test-policy", DetectorVersion: "9",
		Results: []analysis.ResourceAnalysis{
			{Target: target, Resource: analysis.ResourceCPU},
			{Target: target, Resource: analysis.ResourceMemory, Evidence: evidence,
				OOMAdjustment: &analysis.OOMAdjustment{OOMRequestFloorBytes: 96 * mi},
				Recommendations: []analysis.Recommendation{
					{Setting: analysis.SettingRequests, CurrentValue: 8 * mi, SuggestedValue: 100 * mi},
					{Setting: analysis.SettingLimits, CurrentValue: 64 * mi, SuggestedValue: 100 * mi},
				}},
		},
	}
}

func TestAKSOOMPairedPatch(t *testing.T) {
	target, output := oomResult()
	holds := map[analysis.Resource]string{analysis.ResourceCPU: "HPA detected"}
	doc, err := Build("synthetic-cluster", "", target, 1234, output, holds)
	if err != nil {
		t.Fatal(err)
	}
	patch := `{"metadata":{"uid":"synthetic-uid"},"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"memory":"104857600"},"requests":{"memory":"104857600"}}}]}}}}`
	if string(doc.Artifact.Patch) != patch || len(doc.Artifact.Holds) != 1 {
		t.Fatalf("patch %s, holds %+v", doc.Artifact.Patch, doc.Artifact.Holds)
	}
	change := doc.Artifact.Changes[0]
	if len(change.RequestWhy) != 1 || len(change.LimitWhy) != 1 {
		t.Fatal("missing explanation for a proposed resource setting")
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var read Document
	if err := json.Unmarshal(raw, &read); err != nil {
		t.Fatal(err)
	}
	if err := read.Verify(); err != nil {
		t.Fatal(err)
	}
	read.Artifact.Target.Release = "changed"
	if err := read.Verify(); err == nil {
		t.Fatal("changed release passed digest verification")
	}
	if !UnsafeStandalone(output.Results[1]) {
		t.Fatal("legacy singleton commands must be suppressed")
	}
	output.Results[1].Recommendations = output.Results[1].Recommendations[:1]
	if !UnsafeStandalone(output.Results[1]) {
		t.Fatal("single request above the existing limit must not advertise a command")
	}
	if _, err := Build("synthetic-cluster", "", target, 1234, output, nil); err == nil || !strings.Contains(err.Error(), "exceeds the resulting limit") {
		t.Fatalf("request-only error: %v", err)
	}
}

func TestBeforeStateMustMatch(t *testing.T) {
	target, output := oomResult()
	output.Results[1].Recommendations[0].CurrentValue = 7 * mi
	if _, err := Build("synthetic-cluster", "", target, 1234, output, nil); err == nil {
		t.Fatal("stale recommendation accepted")
	}
	output.Results[1].Evidence.CurrentLimit.Available = false
	if _, err := Build("synthetic-cluster", "", target, 1234, output, nil); err == nil {
		t.Fatal("unknown limit accepted")
	}
}

func TestVerifyRejectsMismatchedPayload(t *testing.T) {
	target, output := oomResult()
	doc, err := Build("synthetic-cluster", "", target, 1234, output, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc.Artifact.Patch = json.RawMessage(`{"spec":{}}`)
	doc.Digest, err = checksum(doc.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Verify(); err == nil {
		t.Fatal("unrelated payload passed verification with a matching digest")
	}
}

func TestCPUConversionNoiseAndUnsetLimit(t *testing.T) {
	target, output := oomResult()
	result := &output.Results[0]
	result.Evidence = output.Results[1].Evidence
	result.Evidence.CurrentRequest = analysis.Signal{Available: true, Value: 1000.9999999999999}
	result.Evidence.CurrentLimit = analysis.Signal{Available: true, Unset: true}
	result.Recommendations = []analysis.Recommendation{
		{Setting: analysis.SettingRequests, CurrentValue: 1001.0000000000001, SuggestedValue: 1100.0000000000002},
	}
	doc, err := Build("cluster", "", target, 1234, output, nil)
	if err != nil || doc.Verify() != nil || doc.Artifact.PatchType != StrategicMergePatch ||
		!strings.Contains(string(doc.Artifact.Patch), `"cpu":"1100m"`) || UnsafeStandalone(*result) {
		t.Fatalf("unexpected artifact: %+v, %v", doc, err)
	}
	doc.Artifact.PatchType = "application/merge-patch+json"
	if doc.Verify() == nil {
		t.Fatal("incorrect patch type accepted")
	}
	result.Evidence.CurrentRequest.Value = 1001.5
	if _, err := Build("cluster", "", target, 1234, output, nil); err == nil {
		t.Fatal("fractional millicore baseline accepted")
	}
}

func TestRequestIncreaseWithExplicitZeroLimitIsWithheld(t *testing.T) {
	target, output := oomResult()
	result := &output.Results[1]
	result.Evidence.CurrentRequest = analysis.Signal{Available: true, Value: 0}
	result.Evidence.CurrentLimit = analysis.Signal{Available: true, Value: 0}
	result.Recommendations = []analysis.Recommendation{{Setting: analysis.SettingRequests, SuggestedValue: 104857600}}
	if !UnsafeStandalone(*result) {
		t.Fatal("standalone request increase exceeds the explicit limit")
	}
	if _, err := Build("cluster", "", target, 1234, output, nil); err == nil || !strings.Contains(err.Error(), "exceeds the resulting limit") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestLimitOnlyChangeWithUnsetRequestIsWithheld(t *testing.T) {
	target, output := oomResult()
	result := &output.Results[1]
	result.Evidence.CurrentRequest = analysis.Signal{Available: true, Unset: true}
	result.Recommendations = result.Recommendations[1:]
	if !UnsafeStandalone(*result) {
		t.Fatal("implicit Pod request change was advertised")
	}
	if _, err := Build("cluster", "", target, 1234, output, nil); err == nil || !strings.Contains(err.Error(), "request defaulting") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestRequestWithInheritedLimitBaselineIsWithheld(t *testing.T) {
	target, output := oomResult()
	result := &output.Results[1]
	result.Evidence.CurrentRequest = analysis.Signal{Available: true, Unset: true}
	result.Recommendations = []analysis.Recommendation{
		{Setting: analysis.SettingRequests, CurrentUnset: true, SuggestedValue: 32 * 1024 * 1024},
	}
	if !UnsafeStandalone(*result) {
		t.Fatal("a request with an inherited baseline should be withheld")
	}
	if _, err := Build("cluster", "", target, 1234, output, nil); err == nil || !strings.Contains(err.Error(), "baseline may be inherited") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestUnknownCPUSettingDoesNotDiscardMemoryPair(t *testing.T) {
	target, out := oomResult()
	cpu := &out.Results[0]
	cpu.Evidence = out.Results[1].Evidence
	cpu.Evidence.CurrentLimit.Available = false
	cpu.Recommendations = []analysis.Recommendation{{Setting: analysis.SettingRequests, CurrentValue: 1000, SuggestedValue: 250}}
	doc, err := Build("cluster", "", target, 1234, out, nil)
	if err != nil || doc.Verify() != nil || len(doc.Artifact.Holds) != 1 || doc.Artifact.Holds[0].Resource != analysis.ResourceCPU ||
		len(doc.Artifact.Changes) != 1 || doc.Artifact.Changes[0].Resource != analysis.ResourceMemory ||
		doc.Artifact.Changes[0].After.Request == nil || doc.Artifact.Changes[0].After.Limit == nil {
		t.Fatalf("partial review: %+v %v", doc, err)
	}
	cpu.Evidence.Identity.WorkloadUID = "another"
	if _, err = Build("cluster", "", target, 1234, out, nil); err == nil {
		t.Fatal("global identity mismatch allowed partial export")
	}
}

func TestOfflineChecksMatchConnectedReview(t *testing.T) {
	want := []Check{{Name: "target", Status: Unperformed}, {Name: "revision", Status: Unperformed}, {Name: "currentResources", Status: Unperformed}, {Name: "freshness", Status: Unperformed}}
	if got := UnperformedChecks(); !slices.Equal(want, got) {
		t.Fatalf("offline review checks = %+v, want %+v", got, want)
	}
}

func TestSelectedResourceKeepsOriginalEvidenceAndPair(t *testing.T) {
	target, out := oomResult()
	cpu := &out.Results[0]
	cpu.Evidence = out.Results[1].Evidence
	cpu.Evidence.CurrentRequest.Value = 500
	cpu.Evidence.CurrentLimit.Value = 1000
	cpu.Recommendations = []analysis.Recommendation{{Setting: analysis.SettingRequests, CurrentValue: 500, SuggestedValue: 100}}
	both, err := Build("cluster", "", target, 1234, out, nil)
	if err != nil || len(both.Artifact.Changes) != 2 {
		t.Fatalf("full review: %+v %v", both, err)
	}
	mem, err := BuildForResource("cluster", "", target, 1234, out, nil, analysis.ResourceMemory)
	if err != nil || mem.Verify() != nil || len(mem.Artifact.Changes) != 1 || mem.Artifact.Changes[0].Resource != analysis.ResourceMemory || mem.Artifact.EvidenceFingerprint != both.Artifact.EvidenceFingerprint {
		t.Fatalf("selected review: %+v %v", mem, err)
	}
	cpu.Evidence.CurrentLimit.Available = false
	mem, err = BuildForResource("cluster", "", target, 1234, out, nil, analysis.ResourceMemory)
	if err != nil || len(mem.Artifact.Holds) != 1 || mem.Artifact.Holds[0].Resource != analysis.ResourceCPU {
		t.Fatalf("lost sibling hold: %+v %v", mem, err)
	}
	if _, err := BuildForResource("cluster", "", target, 1234, out, nil, analysis.ResourceCPU); err == nil {
		t.Fatal("held CPU selection exported a sibling memory change")
	}
}
