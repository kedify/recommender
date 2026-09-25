// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.
package analysis

import (
	"fmt"
	"sort"
)

// NormalizeSamples uses the analyzer's native sample conversion. It never mutates
// input. CPU counters become millicores; gauge values retain their units.
func NormalizeSamples(s Series, start, end int64) ([]Sample, error) {
	if s.Kind != SampleGauge && s.Kind != SampleCPUCounterSeconds {
		return nil, fmt.Errorf("unsupported sample kind %q", s.Kind)
	}
	raw := append([]Sample(nil), s.Samples...)
	sort.Slice(raw, func(i, j int) bool { return raw[i].Timestamp < raw[j].Timestamp })
	clean := make([]Sample, 0, len(raw))
	for _, v := range raw {
		if v.Timestamp < start || v.Timestamp > end {
			continue
		}
		if !finite(v.Value) || v.Value < 0 {
			return nil, fmt.Errorf("sample values must be finite and nonnegative")
		}
		if len(clean) > 0 && v.Timestamp == clean[len(clean)-1].Timestamp {
			if v.Value != clean[len(clean)-1].Value {
				return nil, fmt.Errorf("conflicting samples at one source timestamp")
			}
			continue
		}
		clean = append(clean, v)
	}
	if len(clean) == 0 {
		return nil, nil
	}
	values := make([]Sample, 0, len(clean))
	if s.Kind == SampleCPUCounterSeconds {
		for i := 1; i < len(clean); i++ {
			dt := float64(clean[i].Timestamp-clean[i-1].Timestamp) / 1000
			delta := clean[i].Value - clean[i-1].Value
			if delta < 0 {
				delta = clean[i].Value
			}
			rate := delta / dt * 1000
			if !finite(rate) {
				return nil, fmt.Errorf("CPU rate overflow")
			}
			values = append(values, Sample{Value: rate, Timestamp: clean[i].Timestamp})
		}
	} else {
		values = append(values, clean...)
	}

	return values, nil
}
