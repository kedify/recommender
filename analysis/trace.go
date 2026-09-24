// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0

package analysis

// DecisionTrace describes executed sizing branches, in native units (CPU
// millicores, memory bytes). It is evidence, never an alternative sizing engine.
type DecisionTrace struct {
	Version   string            `json:"version"`
	Source    UsageSource       `json:"source"`
	Fallbacks []FallbackAttempt `json:"fallbacks,omitempty"`
	Settings  []SettingTrace    `json:"settings"`
}
type UsageSource struct {
	Release    string  `json:"release"`
	SeriesID   string  `json:"seriesID,omitempty"`
	PodUID     string  `json:"podUID,omitempty"`
	Timestamp  int64   `json:"timestamp,omitempty"`
	Method     string  `json:"method"`
	Percentile float64 `json:"percentile,omitempty"`
}
type FallbackAttempt struct {
	Release  string   `json:"release"`
	Selected bool     `json:"selected"`
	Reasons  []Reason `json:"reasons,omitempty"`
}
type SettingTrace struct {
	Setting     Setting        `json:"setting"`
	Disposition string         `json:"disposition"`
	Reasons     []Reason       `json:"reasons,omitempty"`
	Steps       []DecisionStep `json:"steps,omitempty"`
}
type DecisionStep struct {
	Rule   string             `json:"rule"`
	Values map[string]float64 `json:"values,omitempty"`
	Passed *bool              `json:"passed,omitempty"`
}

func (t *SettingTrace) step(rule string, values map[string]float64) {
	t.Steps = append(t.Steps, DecisionStep{Rule: rule, Values: values})
}
func (t *SettingTrace) guard(rule string, passed bool, values map[string]float64) {
	t.Steps = append(t.Steps, DecisionStep{Rule: rule, Passed: &passed, Values: values})
}
func (t *SettingTrace) stop(disposition string, reasons ...Reason) {
	t.Disposition, t.Reasons = disposition, append([]Reason(nil), reasons...)
}
