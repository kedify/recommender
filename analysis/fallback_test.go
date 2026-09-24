// Copyright Kedify Inc.
// SPDX-License-Identifier: LicenseRef-Kedify-Commercial-1.0 AND LicenseRef-Kedify-Public-Source-1.0

package analysis

import (
	"reflect"
	"testing"
)

func previousFixture(name string, end, duration, step int64) PreviousRelease {
	base := fixture(duration, step).Containers[0]
	start := end - duration*1000
	for _, resource := range []*ResourceObservation{&base.CPU, &base.Memory} {
		resource.Series[0].Release = name
		resource.Series[0].ID = name
		for i := range resource.Series[0].Samples {
			resource.Series[0].Samples[i].Timestamp += start - epoch
		}
	}
	return PreviousRelease{Release: name, ReleaseStartedAt: start, EvaluationTime: end, CPU: base.CPU.Series, Memory: base.Memory.Series}
}

func fallbackFixture() Input {
	in := fixture(600, 30)
	in.WindowStart = epoch - 24*3600000
	return in
}

func TestPreviousRolloutsAreTriedInOrderAndNeverPooled(t *testing.T) {
	for _, eligible := range []int{0, 1, 2, 3, -1} {
		in := fallbackFixture()
		for i, name := range []string{"previous", "second", "third", "fourth"} {
			duration, step := int64(1200), int64(10) // Enough samples, insufficient history.
			if i == eligible {
				duration, step = 3600, 30
			}
			in.Containers[0].PreviousReleases = append(in.Containers[0].PreviousReleases, previousFixture(name, epoch-int64(i+1)*3*3600000, duration, step))
		}
		out := run(t, in, Policy{})
		for _, result := range out.Results {
			if eligible < 0 || eligible >= MaxPreviousReleases {
				if result.RolloutFallback != nil || result.DataQuality.Status != DataQualityUnavailable || len(result.Recommendations) != 0 {
					t.Fatalf("pooled short histories or searched a fourth rollout: %+v", result)
				}
				continue
			}
			want := in.Containers[0].PreviousReleases[eligible]
			fallback := result.RolloutFallback
			if fallback == nil || fallback.Release != want.Release || len(result.Recommendations) == 0 {
				t.Fatalf("did not choose newest eligible previous rollout: %+v", result)
			}
			if fallback.EvaluationTime != want.EvaluationTime || result.Evidence.AggregatedUsage.Timestamp > want.EvaluationTime || result.DataQuality.ObservedEnd > want.EvaluationTime {
				t.Fatal("historical observations were stamped with today's time")
			}
			if result.Target.Release != "A" || result.Evidence.Identity != in.Containers[0].Identity || result.Evidence.CurrentRequest.Timestamp != in.EvaluationTime {
				t.Fatal("fallback replaced the current target or allocation snapshot")
			}
			if !has(fallback.CurrentDataQuality, ReasonInsufficientHistory) || fallback.CurrentDataQuality.Status != DataQualityUnavailable {
				t.Fatal("current rollout's failed evidence guard was lost")
			}
		}
	}
}

func TestFallbackIsIndependentPerResource(t *testing.T) {
	in := fallbackFixture()
	previous := previousFixture("previous", epoch-60000, 7200, 30)
	previous.CPU[0].Samples = previous.CPU[0].Samples[:1]
	in.Containers[0].PreviousReleases = []PreviousRelease{previous, previousFixture("second", epoch-4*3600000, 3600, 30)}
	out := run(t, in, Policy{})
	if out.Results[0].RolloutFallback.Release != "previous" || out.Results[1].RolloutFallback.Release != "second" {
		t.Fatalf("resource histories were coupled: %+v", out.Results)
	}
}

func TestEligibleCurrentRolloutAlwaysWins(t *testing.T) {
	in := fixture(7200, 30)
	in.WindowStart = epoch - 24*3600000
	want := run(t, in, Policy{})
	in.Containers[0].PreviousReleases = []PreviousRelease{previousFixture("previous", epoch-60000, 7200, 30)}
	got := run(t, in, Policy{})
	if !reflect.DeepEqual(got, want) {
		t.Fatal("previous rollout affected an eligible current rollout")
	}
}

func TestFallbackRetainsIdentityAllocationAndInventoryGuards(t *testing.T) {
	for _, mode := range []string{"ambiguous", "missing identity", "stale identity", "missing request", "stale request", "unknown inventory", "foreign usage"} {
		t.Run(mode, func(t *testing.T) {
			in := fallbackFixture()
			c := &in.Containers[0]
			c.PreviousReleases = []PreviousRelease{previousFixture("previous", epoch-60000, 7200, 30)}
			switch mode {
			case "ambiguous":
				c.Identity.Ambiguous = true
			case "missing identity":
				c.Identity.Available = false
			case "stale identity":
				c.Identity.Timestamp = epoch
			case "missing request":
				c.CPU.CurrentRequest.Available, c.Memory.CurrentRequest.Available = false, false
			case "stale request":
				c.CPU.CurrentRequest.Timestamp, c.Memory.CurrentRequest.Timestamp = epoch, epoch
			case "unknown inventory":
				c.Inventory.Available = false
			case "foreign usage":
				c.PreviousReleases[0].CPU[0].WorkloadUID = "another-workload"
				c.PreviousReleases[0].Memory[0].WorkloadUID = "another-workload"
			}
			for _, result := range run(t, in, Policy{}).Results {
				if len(result.Recommendations) != 0 {
					t.Fatalf("fallback bypassed %s guard: %+v", mode, result)
				}
			}
		})
	}
}

func TestFallbackRequiresHistoricalCoverage(t *testing.T) {
	in := fallbackFixture()
	previous := previousFixture("previous", epoch-60000, 7200, 30)
	for _, rows := range [][]Series{previous.CPU, previous.Memory} {
		rows[0].Samples = append(rows[0].Samples[:60], rows[0].Samples[140:]...)
	}
	in.Containers[0].PreviousReleases = []PreviousRelease{previous, previousFixture("second", epoch-4*3600000, 3600, 30)}
	for _, result := range run(t, in, Policy{}).Results {
		if result.RolloutFallback == nil || result.RolloutFallback.Release != "second" {
			t.Fatalf("sparse historical usage authorized sizing: %+v", result)
		}
	}
}

func TestFallbackHandlesMissingCurrentSamplesWithoutBorrowingInventory(t *testing.T) {
	in := fallbackFixture()
	c := &in.Containers[0]
	c.CPU.Series = nil
	c.PreviousReleases = []PreviousRelease{previousFixture("previous", epoch-60000, 7200, 30)}
	result := run(t, in, Policy{}).Results[1]
	if result.RolloutFallback == nil || !has(result.RolloutFallback.CurrentDataQuality, ReasonMissingUsage) || !has(result.DataQuality, ReasonIncompleteInventory) || len(result.Recommendations) != 0 {
		t.Fatalf("historical pod counts authorized downsizing a currently unobserved pod: %+v", result)
	}
}

func TestFallbackKeepsCurrentOOMProtection(t *testing.T) {
	in := fallbackFixture()
	c := &in.Containers[0]
	c.PreviousReleases = []PreviousRelease{previousFixture("previous", epoch-60000, 7200, 30)}
	c.OOMKills = []OOMKill{
		{ID: "current-oom", WorkloadUID: "uid", Release: "A", Timestamp: in.EvaluationTime - 60000, MemoryLimitBytes: 1024 * 1024 * 1024},
		{ID: "old-oom", WorkloadUID: "uid", Release: "previous", Timestamp: epoch - 120000, MemoryLimitBytes: 4 * 1024 * 1024 * 1024},
	}
	result := run(t, in, Policy{}).Results[0]
	if result.RolloutFallback == nil || result.OOMAdjustment == nil || result.OOMAdjustment.OOMRequestFloorBytes != 1.5*1024*1024*1024 || len(result.Evidence.OOMKills) != 1 || result.Evidence.OOMKills[0].ID != "current-oom" {
		t.Fatalf("fallback changed current OOM protection: %+v", result)
	}
}
