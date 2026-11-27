// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

// Package reviewpatch builds a review-only patch from the output of resource analysis.
package reviewpatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/kedify/recommender/analysis"
)

const SchemaVersion = "insights-resource-patch/v1"

// StrategicMergePatch describes the Kubernetes patch format hashed in the artifact.
const StrategicMergePatch = "application/strategic-merge-patch+json"

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type Document struct {
	Artifact Artifact `json:"artifact"`
	Digest   string   `json:"digest"`
}

// Artifact is hashed as compact encoding/json output using this field order.
// Maps in the patch use lexicographic key order. Live checks are outside the digest.
type Artifact struct {
	SchemaVersion       string          `json:"schemaVersion"`
	Cluster             string          `json:"cluster"`
	Shard               string          `json:"shard,omitempty"`
	APIVersion          string          `json:"apiVersion"`
	PatchType           string          `json:"patchType"`
	Target              analysis.Target `json:"target"`
	EvaluatedAt         int64           `json:"evaluatedAt"` // Unix milliseconds.
	PolicyVersion       string          `json:"policyVersion"`
	DetectorVersion     string          `json:"detectorVersion"`
	EvidenceFingerprint string          `json:"evidenceFingerprint"`
	Changes             []Change        `json:"changes"`
	Holds               []Hold          `json:"holds,omitempty"`
	Patch               json.RawMessage `json:"patch"`
}

type Hold struct {
	Resource analysis.Resource `json:"resource"`
	Reason   string            `json:"reason"`
}

type Change struct {
	Resource   analysis.Resource `json:"resource"`
	Before     Values            `json:"before"`
	After      Values            `json:"after"`
	RequestWhy []string          `json:"requestWhy,omitempty"`
	LimitWhy   []string          `json:"limitWhy,omitempty"`
}

// Values are millicores for CPU and bytes for memory. Null means unset.
// Changes require both the request and limit to be known.
type Values struct {
	Request *int64 `json:"request,string"`
	Limit   *int64 `json:"limit,string"`
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

const (
	Passed      = "passed"
	Failed      = "failed"
	Unperformed = "unperformed"
)

type Review struct {
	Document        Document `json:"document"`
	Checks          []Check  `json:"checks"`
	CheckedAt       int64    `json:"checkedAt,omitempty"` // Unix milliseconds.
	Generation      int64    `json:"generation,omitempty"`
	ResourceVersion string   `json:"resourceVersion,omitempty"`
}

// UnperformedChecks lists the four connected read-only validations for a saved
// review. Applying a patch and checking admission or write access are separate.
func UnperformedChecks() []Check {
	return []Check{
		{Name: "target", Status: Unperformed},
		{Name: "revision", Status: Unperformed},
		{Name: "currentResources", Status: Unperformed},
		{Name: "freshness", Status: Unperformed},
	}
}

func ValidateTarget(target analysis.Target) error {
	if target.Kind != "Deployment" || target.WorkloadUID == "" || target.Release == "" {
		return errors.New("review requires an apps/v1 Deployment UID and release")
	}
	if len(target.Name) > 253 || !validLabel(target.Namespace) || !validLabel(target.Container) {
		return errors.New("invalid Deployment target, namespace or container")
	}
	for _, label := range strings.Split(target.Name, ".") {
		if !validLabel(label) {
			return errors.New("invalid Deployment name")
		}
	}
	return nil
}

func validLabel(value string) bool {
	return len(value) <= 63 && dnsLabel.MatchString(value)
}

// Build exports one regular container. The caller supplies holds established by
// its source, such as a utilization autoscaler affecting the targeted resource.
func Build(cluster, shard string, target analysis.Target, evaluatedAt int64, out *analysis.Output, holds map[analysis.Resource]string) (Document, error) {
	return build(cluster, shard, target, evaluatedAt, out, holds, "")
}

// BuildForResource reviews the selected recommendation's request and limit as
// a pair. The digest still covers both resources' original target evidence.
func BuildForResource(cluster, shard string, target analysis.Target, evaluatedAt int64, out *analysis.Output, holds map[analysis.Resource]string, selected analysis.Resource) (Document, error) {
	if selected != analysis.ResourceCPU && selected != analysis.ResourceMemory {
		return Document{}, errors.New("select cpu or memory for resource review")
	}
	return build(cluster, shard, target, evaluatedAt, out, holds, selected)
}

func build(cluster, shard string, target analysis.Target, evaluatedAt int64, out *analysis.Output, holds map[analysis.Resource]string, selected analysis.Resource) (Document, error) {
	if err := ValidateTarget(target); err != nil {
		return Document{}, err
	}
	if strings.TrimSpace(cluster) == "" || evaluatedAt <= 0 || out == nil ||
		out.PolicyVersion == "" || out.DetectorVersion == "" || out.SchemaVersion != analysis.OutputSchemaVersion {
		return Document{}, errors.New("review requires cluster scope, evaluation time and versioned analysis")
	}

	artifact := Artifact{
		SchemaVersion: SchemaVersion, Cluster: cluster, Shard: shard, APIVersion: "apps/v1", PatchType: StrategicMergePatch,
		Target: target, EvaluatedAt: evaluatedAt, PolicyVersion: out.PolicyVersion, DetectorVersion: out.DetectorVersion,
	}
	evidence := make([]analysis.ResourceAnalysis, 0, 2)
	for _, resource := range []analysis.Resource{analysis.ResourceCPU, analysis.ResourceMemory} {
		result, err := findResult(out.Results, target, resource)
		if err != nil {
			return Document{}, err
		}
		if result == nil {
			continue
		}
		evidence = append(evidence, *result)
		if reason := holds[resource]; reason != "" {
			artifact.Holds = append(artifact.Holds, Hold{Resource: resource, Reason: reason})
			continue
		}
		if len(result.Recommendations) == 0 {
			continue
		}
		identity := result.Evidence.Identity
		if !identity.Available || identity.Ambiguous || identity.WorkloadUID != target.WorkloadUID || identity.Release != target.Release {
			return Document{}, errors.New("current workload identity is unknown")
		}
		if !result.Evidence.CurrentRequest.Available || !result.Evidence.CurrentLimit.Available {
			artifact.Holds = append(artifact.Holds, Hold{Resource: resource, Reason: "current request or limit is unknown"})
			continue
		}
		if selected != "" && resource != selected {
			continue
		}
		change, err := buildChange(*result)
		if err != nil {
			return Document{}, fmt.Errorf("%s: %w", resource, err)
		}
		if !equal(change.Before.Request, change.After.Request) || !equal(change.Before.Limit, change.After.Limit) {
			artifact.Changes = append(artifact.Changes, change)
		}
	}
	if len(artifact.Changes) == 0 {
		return Document{}, errors.New("no eligible resource changes for the selected container")
	}
	var err error
	artifact.EvidenceFingerprint, err = checksum(evidence)
	if err != nil {
		return Document{}, err
	}
	artifact.Patch, err = renderPatch(artifact)
	if err != nil {
		return Document{}, err
	}
	digest, err := checksum(artifact)
	if err != nil {
		return Document{}, err
	}
	return Document{Artifact: artifact, Digest: digest}, nil
}

func findResult(results []analysis.ResourceAnalysis, target analysis.Target, resource analysis.Resource) (*analysis.ResourceAnalysis, error) {
	var selected *analysis.ResourceAnalysis
	for i := range results {
		row := &results[i]
		if row.Target != target || row.Resource != resource {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("ambiguous %s analysis for the selected container", resource)
		}
		selected = row
	}
	return selected, nil
}

func buildChange(result analysis.ResourceAnalysis) (Change, error) {
	request, err := currentValue(result.Resource, result.Evidence.CurrentRequest)
	if err != nil {
		return Change{}, err
	}
	limit, err := currentValue(result.Resource, result.Evidence.CurrentLimit)
	if err != nil {
		return Change{}, err
	}
	values := Values{Request: request, Limit: limit}
	change := Change{Resource: result.Resource, Before: values, After: values}
	seen := map[analysis.Setting]bool{}
	for _, row := range result.Recommendations {
		if seen[row.Setting] {
			return Change{}, errors.New("duplicate recommendation setting")
		}
		seen[row.Setting] = true
		next := math.Ceil(snapQuantity(result.Resource, row.SuggestedValue))
		if !representable(next) || next == 0 {
			return Change{}, errors.New("suggested quantity is out of range")
		}
		value := int64(next)
		switch row.Setting {
		case analysis.SettingRequests:
			if !matchesRecommendation(result.Resource, request, row) {
				return Change{}, errors.New("request recommendation baseline differs from evidence")
			}
			change.After.Request = &value
			change.RequestWhy = reasons(result, row.Setting)
		case analysis.SettingLimits:
			if !matchesRecommendation(result.Resource, limit, row) {
				return Change{}, errors.New("limit recommendation baseline differs from evidence")
			}
			change.After.Limit = &value
			change.LimitWhy = reasons(result, row.Setting)
		default:
			return Change{}, errors.New("unsupported recommendation setting")
		}
	}
	if err := validateChange(change); err != nil {
		return Change{}, err
	}
	return change, nil
}

func reasons(result analysis.ResourceAnalysis, setting analysis.Setting) []string {
	var reasons []string
	if result.OOMAdjustment != nil {
		if setting == analysis.SettingRequests {
			reasons = append(reasons, "oom-request-floor")
		} else {
			reasons = append(reasons, "limit-derived-from-oom-request")
		}
	}
	if result.DecisionTrace != nil {
		for _, trace := range result.DecisionTrace.Settings {
			if trace.Setting == setting {
				for _, reason := range trace.Reasons {
					reasons = append(reasons, string(reason))
				}
			}
		}
	}
	return reasons
}

func representable(value float64) bool {
	return value >= 0 && value < 1<<53 && math.Trunc(value) == value
}

func currentValue(resource analysis.Resource, signal analysis.Signal) (*int64, error) {
	if !signal.Available {
		return nil, errors.New("current request or limit is unknown")
	}
	if signal.Unset {
		return nil, nil
	}
	canonical := snapQuantity(resource, signal.Value)
	if !representable(canonical) {
		return nil, errors.New("current quantity is out of range")
	}
	value := int64(canonical)
	return &value, nil
}

func matchesRecommendation(resource analysis.Resource, current *int64, row analysis.Recommendation) bool {
	if current == nil {
		return row.CurrentUnset
	}
	return !row.CurrentUnset && float64(*current) == snapQuantity(resource, row.CurrentValue)
}

// CPU sources can multiply cores by 1000 and leave a few floating-point
// ulps around an integral millicore value. Keep actual fractional values.
func snapQuantity(kind analysis.Resource, value float64) float64 {
	if kind != analysis.ResourceCPU || value < 0 || value >= 1<<53 {
		return value
	}
	rounded := math.Round(value)
	ulp := math.Nextafter(rounded, math.Inf(1)) - rounded
	if math.Abs(value-rounded) <= min(4*ulp, 0.000001) {
		return rounded
	}
	return value
}

func validateChange(change Change) error {
	if change.After.Request == nil && !equal(change.Before.Limit, change.After.Limit) {
		return errors.New("a limit change with an unset request would change Pod request defaulting")
	}
	if change.After.Request != nil && change.After.Limit != nil && *change.After.Request > *change.After.Limit {
		return errors.New("proposed request exceeds the resulting limit")
	}
	if change.Before.Request == nil && change.Before.Limit != nil && *change.Before.Limit > 0 && change.After.Request != nil {
		return errors.New("the effective request baseline may be inherited from the existing limit")
	}
	return nil
}

func equal(a, b *int64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// UnsafeStandalone reports whether a recommendation on its own would violate
// request <= limit or implicitly change the request through Pod defaulting.
func UnsafeStandalone(result analysis.ResourceAnalysis) bool {
	for _, row := range result.Recommendations {
		suggested := math.Ceil(snapQuantity(result.Resource, row.SuggestedValue))
		switch row.Setting {
		case analysis.SettingRequests:
			limit := result.Evidence.CurrentLimit
			request := result.Evidence.CurrentRequest
			if limit.Available && !limit.Unset &&
				(suggested > snapQuantity(result.Resource, limit.Value) || request.Available && request.Unset && limit.Value > 0) {
				return true
			}
		case analysis.SettingLimits:
			request := result.Evidence.CurrentRequest
			if request.Available && (request.Unset || suggested < snapQuantity(result.Resource, request.Value)) {
				return true
			}
		}
	}
	return false
}

func renderPatch(artifact Artifact) (json.RawMessage, error) {
	settings := map[string]map[analysis.Resource]string{}
	seen := map[analysis.Resource]bool{}
	for _, change := range artifact.Changes {
		if (change.Resource != analysis.ResourceCPU && change.Resource != analysis.ResourceMemory) || seen[change.Resource] {
			return nil, errors.New("unsupported or duplicate patch resource")
		}
		seen[change.Resource] = true
		if err := validateChange(change); err != nil {
			return nil, err
		}
		for _, pair := range []struct {
			key           string
			before, after *int64
		}{{"requests", change.Before.Request, change.After.Request}, {"limits", change.Before.Limit, change.After.Limit}} {
			if equal(pair.before, pair.after) {
				continue
			}
			if pair.after == nil || *pair.after <= 0 {
				return nil, errors.New("patch requires a positive quantity for each changed setting")
			}
			if settings[pair.key] == nil {
				settings[pair.key] = map[analysis.Resource]string{}
			}
			value := fmt.Sprint(*pair.after)
			if change.Resource == analysis.ResourceCPU {
				value += "m"
			}
			settings[pair.key][change.Resource] = value
		}
	}
	if len(settings) == 0 {
		return nil, errors.New("patch contains no effective changes")
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]string{"uid": artifact.Target.WorkloadUID},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []map[string]any{{"name": artifact.Target.Container, "resources": settings}},
		}}},
	})
}

// Verify checks patch consistency and the stored digest. It does not authorize a change.
func (d Document) Verify() error {
	if d.Artifact.SchemaVersion != SchemaVersion || d.Artifact.APIVersion != "apps/v1" || d.Artifact.PatchType != StrategicMergePatch {
		return errors.New("unsupported review patch schema")
	}
	if err := ValidateTarget(d.Artifact.Target); err != nil {
		return err
	}
	canonical, err := renderPatch(d.Artifact)
	if err != nil {
		return err
	}
	var patch any
	if err := json.Unmarshal(d.Artifact.Patch, &patch); err != nil {
		return err
	}
	encoded, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, encoded) {
		return errors.New("patch does not match the reviewed settings")
	}
	d.Artifact.Patch = canonical
	digest, err := checksum(d.Artifact)
	if err != nil {
		return err
	}
	if digest != d.Digest {
		return errors.New("review patch digest mismatch")
	}
	return nil
}

func checksum(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}
