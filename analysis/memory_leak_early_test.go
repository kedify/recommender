// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0
// See LICENSE and PUBLIC_SOURCE_LICENSE.

package analysis

import (
	"encoding/json"
	"math"
	"testing"
)

func earlyLeakFixture(minutes int64, profile func(float64) float64) Input {
	in := fixture(minutes*60, 60)
	for i := range in.Containers[0].Memory.Series[0].Samples {
		s := &in.Containers[0].Memory.Series[0].Samples[i]
		s.Value = profile(float64(s.Timestamp-epoch)/3600000) * mib
	}
	return in
}

// Match the demo's 12 MiB allocations every 30 minutes, including monitoring
// beginning late in a lifetime with an already-large baseline.
func earlyDemoProfile(h float64) float64 { return 488 + 12*math.Floor(h*2) }

func TestMemoryLeakDetectsDemoAfterTwoHoursAndWarmup(t *testing.T) {
	for _, minutes := range []int64{120, 149, 150, 180} {
		in := earlyLeakFixture(minutes, earlyDemoProfile)
		leak := run(t, in, leakPolicy()).Results[0].MemoryLeak
		if minutes < 150 {
			if leak.Status != MemoryLeakInsufficientData || leak.Confidence != 0 {
				t.Fatalf("%d minutes bypassed warmup/history: %+v", minutes, leak)
			}
			continue
		}
		if leak.Status != MemoryLeakPotential || leak.Confidence <= 0 || leak.Confidence >= 50 {
			t.Fatalf("early demo should produce a low-confidence finding: %+v", leak)
		}
		e := leak.Episodes[0]
		if e.UsableHistoryHours < 2 || e.Confidence != leak.Confidence {
			t.Fatalf("missing early evidence: %+v", e)
		}
		f := finding(classified(t, in), FeatureMemoryLeak)
		if f.Status != ClassificationDetected || f.MemoryLeak.Confidence != leak.Confidence {
			t.Fatalf("classification did not expose early finding: %+v", f)
		}
		encoded, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		var decoded FeatureFinding
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.MemoryLeak.Confidence != leak.Confidence {
			t.Fatalf("confidence did not survive JSON: %s, %v", encoded, err)
		}
	}
}

func TestMemoryLeakEarlyFalsePositiveGuards(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile func(float64) float64
	}{
		{"flat", func(float64) float64 { return 500 }},
		{"startup", func(h float64) float64 { return 100 + 300*math.Min(h*2, 1) }},
		{"single step", func(h float64) float64 {
			if h < 1.5 {
				return 500
			}
			return 700
		}},
		{"recent plateau", func(h float64) float64 { return earlyDemoProfile(math.Min(h, 1.5)) }},
		{"bounded GC", func(h float64) float64 { return 500 + 64*math.Mod(h*2, 1) }},
		{"small drift", func(h float64) float64 { return 500 + h }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leak := run(t, earlyLeakFixture(150, tc.profile), leakPolicy()).Results[0].MemoryLeak
			if leak.Status != MemoryLeakNoPattern || leak.Confidence != 0 {
				t.Fatalf("early non-leak profile was reported: %+v", leak)
			}
		})
	}
}

func TestMemoryLeakConfidenceReflectsEvidenceStrength(t *testing.T) {
	confidence := func(minutes int64, profile func(float64) float64, sparse bool) int {
		t.Helper()
		in := earlyLeakFixture(minutes, profile)
		if sparse {
			s := &in.Containers[0].Memory.Series[0]
			var kept []Sample
			for i, sample := range s.Samples {
				if i%10 != 1 {
					kept = append(kept, sample)
				}
			}
			s.Samples = kept
		}
		p := leakPolicy()
		p.Evidence.MinimumCoverage = .8
		leak := run(t, in, p).Results[0].MemoryLeak
		if leak.Status != MemoryLeakPotential || leak.Confidence < 1 || leak.Confidence > 95 {
			t.Fatalf("expected bounded positive confidence: %+v", leak)
		}
		return leak.Confidence
	}
	short := confidence(150, earlyDemoProfile, false)
	long := confidence(390, earlyDemoProfile, false)
	stronger := confidence(150, func(h float64) float64 { return 488 + 24*math.Floor(h*2) }, false)
	sparse := confidence(150, earlyDemoProfile, true)
	if long <= short || stronger <= short || sparse >= short {
		t.Fatalf("score must reflect history, growth, and coverage: short=%d long=%d stronger=%d sparse=%d", short, long, stronger, sparse)
	}
}

func TestMemoryLeakEarlyCustomThresholdsRemainEffective(t *testing.T) {
	in := earlyLeakFixture(150, earlyDemoProfile)
	for _, policy := range []MemoryLeakPolicy{
		{MinimumHistorySeconds: 6 * 3600},
		{MinimumGrowthBytes: 64 * mib},
		{MinimumRelativeGrowth: .2},
	} {
		p := leakPolicy()
		p.Memory.LeakDetection = &policy
		if leak := run(t, in, p).Results[0].MemoryLeak; leak.Status == MemoryLeakPotential {
			t.Fatalf("custom threshold ignored: %+v", policy)
		}
	}
}
