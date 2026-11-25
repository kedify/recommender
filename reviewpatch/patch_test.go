// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package reviewpatch

import (
	"encoding/json"
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
