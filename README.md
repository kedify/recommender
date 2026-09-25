# Kedify Recommender

This Go module contains the resource recommendation calculations shared by Kedify
services and the Kedify CLI. It does not query metrics, call Kubernetes, serve
HTTP, or store recommendations.

The `analysis` package accepts normalized per-container observations and a policy.
It returns deterministic CPU and memory request/limit recommendations together
with the evidence and data quality used to produce them.

```go
import "github.com/kedify/recommender/analysis"

output, err := analysis.Analyze(snapshot, policy)
```

Callers fetch raw range vectors and map them into `analysis.Input`; calculations
and CPU counter normalization happen in this package. Input schema v2 rejects v1
input; results use output schema v3 and resource detector version 8. Consumers
should update generated output bindings and invalidate cached findings when upgrading.
All timestamps are original Unix milliseconds, including current settings and
identity. Do not stamp carried-forward values with query evaluation times. CPU
gauges use millicores, memory uses bytes, and `cpu-counter-seconds` uses cumulative
CPU seconds. Adjacent counter observations become millicores using delta / elapsed
seconds × 1000; resets use the post-reset counter value. These are interval-average
rates, including across collection outages; no intermediate observations are
invented, and missing measurements reduce coverage.

Group observations by namespace, workload kind/name and container. The target and
current identity select one workload UID and release. Keep other releases in raw
series so the engine can detect visible rollback boundaries. Each replica/counter
lifetime has a distinct series ID; preserve pod UID when available. Never sum
replica usage into a per-container setting. The engine computes nearest-rank CPU
percentiles per series, then takes the maximum across replicas; memory uses the
maximum of every selected raw observation. Repeated source timestamps count once;
conflicting values at the same timestamp are rejected.

Current identity and settings must be fresh and unambiguous. Supply
`ReleaseStartedAt` from an activation event when available, or leave it zero.
The engine then starts at the first matching observation after the latest observed
other release for that UID. This excludes visible A→B→A history. Output explicitly
marks `releaseStartInferred`: an unobserved intermediate release cannot be detected
from metrics alone. An authoritative activation boundary is needed to resolve that
source limitation. Deleted/recreated workload UIDs are never pooled.

Each resource independently reports observed start/end, distinct sample count,
series count, inferred median cadence and coverage. Coverage
is the union of observed timestamps for the current release across pod lifetimes,
divided by the selected release segment duration rather than pre-release lookback,
with intervals capped at the median source cadence and one cadence of edge
tolerance. Healthy scale-out or pod replacement retains established release history.
`sampleCount` reports all distinct per-series samples; `observationCount` reports
distinct timestamps across series after normalization (including CPU counter
conversion) and is the count checked against `minimumSamples`. Confidence uses unique release
timestamps, measured release history and coverage and is capped at 95. It is also
capped by the history, sample count and coverage of the series supplying the sizing
value; a newly busy replica can justify growth without borrowing another replica's
confidence. Equal sizing values use the strongest independently supporting series.
Only fresh observed pods count against current inventory. Stale samples,
insufficient history, too few samples and insufficient overall coverage block
sizing; an isolated collection outage does not independently veto a recommendation.
The defaults require one hour of observed history, 30 distinct observation times,
90% coverage, and observations no older than five minutes. One hour of minute-level
scrapes can qualify, including modest gaps within the coverage guard. Shortening a
query does not shorten the history guard. A caller can explicitly choose other
minimums through the effective policy; automatic seasonal detection is outside
this package.

Callers may supply `previousReleases`, ordered newest to oldest, on a container
observation. CPU and memory independently fall back when the current rollout has
missing usage, insufficient history, or insufficient samples. At most the first
three previous rollouts are examined. The first candidate passing all usage
quality checks wins; samples from different rollouts are never pooled. An
eligible current rollout always wins, including when it needs no material change.

Each previous rollout supplies its release ID, raw CPU/memory series, and the last
historical evaluation time; an optional activation boundary can be provided.
Historical evidence is evaluated at that time, capped at the current rollout's
start, and retains its original timestamps. `rolloutFallback` in each resource
result identifies the historical source and preserves the current rollout's
failed data-quality checks. The result target, identity, allocation signals,
inventory checks, OOM events, and leak detection remain current. Historical pod
counts cannot authorize downsizing currently unobserved pods. Existing callers
that omit `previousReleases` keep current-rollout-only behavior.

Inventory counts must describe the selected UID/release/container: eligible,
observed eligible, and excluded containers. Mark inventory unavailable when the
source cannot supply that denominator. Unknown, stale, incomplete or excluded
inventory blocks downsizing, including introducing a limit where zero means no
limit. Well-covered usage can still justify growth with partial quality. Inconsistent
current settings across replicas must be marked unavailable by the adapter.

For a current request or limit that is known to be absent, supply
`Signal{Available: true, Unset: true, Timestamp: observedAt}`. This is distinct
from an observed numeric zero and from `Available: false` (unknown). The value
must remain zero when `Unset` is true; it is a placeholder, not an allocation.
Since detector version 7, initializing an unset setting bypasses absolute and
relative minimum-change thresholds. Evidence, freshness, bounds, inventory,
OOM and requests-only guards still apply. In particular, introducing an unset
limit still requires safe inventory and OOM evidence. Numeric signals that omit
`unset` retain their previous behavior, including explicit zero values.
Recommendations mark such initialization with `currentUnset: true`; their
`currentValue` is then only a placeholder. Decision traces record
`initialize unset setting` instead of a change from zero.

Effective policy contains CPU percentile/max, headroom, request/limit ratios,
request-only behavior, resource bounds, material-change thresholds and evidence
guards. Defaults use CPU bounds 20–64,000 millicores and memory bounds 10 MiB–1 TiB;
material change requires both 10% and 50 millicores / 8 MiB. Limits cannot fall below
the retained request. Every resource returns measured evidence and explicit quality
reasons; an empty recommendation list always includes a no-action reason. Detector
and normalized-policy identities are independent from schema versions. Consumers
should pin a released module version and invalidate/recompute old findings.

## OOM observations

Callers may supply `ContainerObservation.OOMKills` as normalized positive OOM
termination events. The engine has no metric names, PromQL, Kubernetes clients,
or source-specific adapters. Each event has a stable `ID`, the original termination
`Timestamp` in Unix milliseconds, `WorkloadUID`, `Release`, optional `PodUID`, and
optional `MemoryLimitBytes` for the finite limit in effect at termination:

```go
container.OOMKills = []analysis.OOMKill{{
    ID:               "pod-uid/app/1800000060000",
    PodUID:           "pod-uid",
    WorkloadUID:      container.Target.WorkloadUID,
    Release:          container.Target.Release,
    Timestamp:        1800000060000,
    MemoryLimitBytes: 512 * 1024 * 1024,
}}
policy := analysis.DefaultPolicy()
policy.Memory.OOMKilledCoefficient = 1.5 // Default: 50% increase after an OOM kill.
```

The adapter must establish the workload/release identity at the event time before
assigning it to this container. Use zero or omit `MemoryLimitBytes` when the
event-time limit is unknown or unlimited; do not substitute today's limit.
Repeated scrapes of one termination retain the same event ID and timestamp.
Identical events are deduplicated; conflicting observations sharing an ID are
rejected. All supplied observations are validated before filtering by time or
workload/release identity. Events are sorted deterministically and input is not mutated.

Only events within the requested window and selected workload UID/release segment
affect memory. Events from before a rollback boundary or from another workload UID
are excluded, as are future events. Event age is not current-signal freshness:
a kill earlier in the selected history still matters even if its pod has gone.
Events do not establish usage coverage. A verified current-release event can
establish an inferred activation boundary when usage samples are absent; known
activation boundaries and observed rollback boundaries still restrict events.

For events with a known limit, the calculation follows KRR's memory rule:

```text
baseline = peak observed memory × memory.headroomCoefficient
OOM floor = maximum event-time memory limit × memory.oomKilledCoefficient
request candidate = max(baseline, OOM floor)
```

For example, a 512 MiB limit exceeded by an OOM produces a 768 MiB floor with the
default coefficient. The normal memory limit/request ratio then applies; set
`memory.limitsToRequestsRatio` to 1 for equal requests and limits, as in KRR.

A timestamp-only event uses the current finite memory limit as its sizing base,
then the current memory request if no finite limit is known, then qualifying
usage as a final fallback. This is recorded as a fallback, never as the historical
failed limit. The coefficient applies once; repeated events do not compound it.
Unknown failed limits still block reductions and introduction of a finite limit,
and produce `unknown-oom-memory-limit`. The largest event contribution wins.
The coefficient must be finite and at least 1; zero selects the default 1.5.

A current-release OOM with a positive sizing base authorizes memory increases
without usage samples, minimum history, coverage, or fresh usage. Missing usage
remains visible as partial data quality, and usage confidence is zero for this
path. No reduction is authorized by insufficient usage. Identity, current-setting
freshness, material-change, bounds, and request/limit consistency guards still
apply. CPU sizing remains usage-based. Omitting the optional events preserves
usage-based sizing; it does not assert that no kills occurred.

Memory output includes:

- `notices: ["oom-kill-detected"]` and `evidence.oomKills`, even if a guard blocks
  recommendations. Detection by itself does not degrade data quality.
- `oomAdjustment` when sizing is eligible: `baselineRequestBytes`,
  `oomRequestFloorBytes`, `usedCurrentFallback`, and `usedUsageFallback` explain the calculation before
  bounds and action filtering. The floor may already be below the baseline, or
  bounds/material-change guards may prevent a resulting recommendation.
- `effectivePolicy.memory.oomKilledCoefficient` records the effective multiplier.

The OOM coefficient is included in the normalized policy hash. Consumers using
this feature must pin a module version containing it and invalidate cached
findings from older detectors/policies.

### Adapter guidance

- **Kedify agent:** `container_last_oom_kill_timestamp` stores the termination
  time in its **value**, in Unix seconds. Convert that value to milliseconds;
  the metric sample timestamp is the collection time. Use the `podUID`,
  `workloadUID`, `workloadRevision`, and container labels to establish identity.
  Construct a stable event ID from pod UID, container, and termination time.
  The timestamp metric itself supplies no memory limit. Attach a limit only if
  historical evidence establishes it at termination. Respect
  `container_oom_collection_status`; absence of series under denied, unavailable,
  or over-budget collection is not proof of zero kills.
- **kube-state-metrics:** join a positive
  `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}` with
  `kube_pod_container_status_last_terminated_timestamp` for the same pod UID and
  container, then convert its timestamp value to milliseconds. Resolve historical
  owner/release identity and, if available, the memory resource limit at the event
  time. A reason gauge alone does not establish the event time; do not stamp it
  with each scrape time. See the [KSM pod metrics reference](https://github.com/kubernetes/kube-state-metrics/blob/main/docs/metrics/workload/pod-metrics.md).
- **Other sources:** Kubernetes termination status, event stores, or offline JSON
  may populate the same structure directly. Do not infer an OOM solely from a
  restart count or exit code. Source collection and conversion belong to callers.

## Optional potential memory-leak detection

Enable the advisory detector when calling the same `Analyze` entry point:

```go
policy := analysis.DefaultPolicy()
policy.Memory.LeakDetection = &analysis.MemoryLeakPolicy{} // Enable defaults.
output, err := analysis.Analyze(snapshot, policy)
```

`nil` (the default) disables detection and omits its policy/output fields. In JSON,
use `"memory": {"leakDetection": {}}` within the policy to enable defaults; omit
`leakDetection` or use `null` to disable it. Nonzero policy fields override defaults.
The detector consumes the existing byte-valued memory gauges and normalized OOM
events; it has no metric names, runtime dependencies, or source-specific adapters.
Keep the memory measurement semantics consistent within a series.

The algorithm looks for a persistently rising **lower baseline**, rather than
ever-higher peaks that may be reclaimed by GC:

1. Select the current workload UID/release segment and the latest 24 hours. Analyze
   each replica/container lifetime separately; do not stitch releases or replicas
   together. Skip the first 30 minutes of each observed lifetime as warmup. A known
   OOM termination also splits an episode when the adapter has reused a series ID.
   Adapters must still give all container lifetimes distinct IDs: non-OOM restarts
   cannot reliably be inferred from a drop in memory usage.
2. Divide each episode into complete 30-minute buckets. Sort the memory values in
   each bucket and take P10: the value at the one-based rank `ceil(0.10 * count)`.
   This estimates the lower baseline and reduces the effect of short-lived peaks;
   it is not a measurement of live heap or a detected GC event.
3. Require at least six hours after warmup and at least 12 usable complete buckets,
   each with five distinct source samples. Skip empty or undersampled buckets;
   they need not be adjacent and are never replaced with zero-valued baselines.
   Apply `evidence.minimumCoverage` to the **whole episode** (default 90%),
   including empty buckets in its denominator. The usable buckets must also
   supply the configured minimum history. Apply `freshnessSeconds` (default five
   minutes) to the episode's final sample. One replica cannot supply another's
   missing coverage. A matching pod's OOM may explain why an episode ended before
   evaluation time if its final sample was fresh at termination. An OOM with
   unknown pod identity cannot establish that link.
4. Fit a robust [Theil–Sen trend](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.theilslopes.html):
   the median slope between every pair of usable bucket baselines, using their
   actual elapsed time so missing buckets do not compress time, implemented locally
   without dependencies. Require a positive slope and at least 80% of earlier/later
   bucket pairs to increase. The median baseline of the last quarter of buckets
   must exceed that of the first quarter by both 64 MiB and 20%. When the starting
   baseline is zero, only the absolute growth threshold applies.
5. Require the trend to continue in the latest quarter (at least six buckets):
   the same 80% consistency threshold and a slope at least 25% of the whole-episode
   slope. This suppresses startup steps, caches that have plateaued, and sustained
   recovery. Correlated OOMs support the finding but never establish a leak alone.

Tune the exposed lookback, bucket duration, warmup, minimum history/samples,
absolute/relative growth, and trend consistency through `MemoryLeakPolicy`.
Durations use seconds; zero fields select defaults. Policies must retain at least
12 buckets of minimum history and at most 256 buckets in the lookback, bounding the
pairwise computation independently of the number of raw samples. P10 and the recent
trend check are fixed parts of detector version `3`.

Each memory result gains `memoryLeak`, including:

- `status`: `potential-leak` if any episode passes the heuristic;
  `no-leak-pattern` if all considered episodes were evaluable and none passes;
  `insufficient-data` when none passes and evidence is incomplete or unavailable.
- The detector version, selected window, evaluated/suspected/skipped episode counts,
  and explicit reasons. A positive finding may coexist with skipped episodes.
  Selected series with no samples in the lookback count as skipped episodes, with
  missing or stale usage reasons; they cannot support a `no-leak-pattern` result.
- Per-episode series/pod identity, observed interval, sample/bucket counts, coverage,
  starting/ending baselines, growth in bytes and as a fraction, overall/recent slopes
  in bytes/hour, and trend consistency. Consistency is a measured fraction of
  increasing pairs, **not a probability of a leak**. `relativeGrowth` is omitted
  when the starting baseline is zero.
- `oomKillIDs` on corroborated episodes, referencing the existing `evidence.oomKills`.
  A positive finding also adds `potential-memory-leak` to the resource's `notices`.

This diagnostic does not modify request/limit recommendations, sizing confidence,
or existing OOM adjustments. Its default six-hour history requirement is
independent of the default one-hour sizing guard. A caller can configure a longer
sizing minimum, allowing leak detection to report a pattern while sizing remains
blocked. Missing resource settings or incomplete inventory do not prevent this
diagnostic; ambiguous/stale workload identity and insufficient usage evidence do.
The normalized policy hash includes enabled detector settings. Enabling the leak
heuristic does not alter resource sizing; it has its own
`memoryLeak.detectorVersion` for cache invalidation.

Treat this as a **potential leak, not a diagnosis**. Growing useful allocations,
unbounded caches, increasing traffic, and allocator retention can look identical
in container memory metrics. Conversely, slow leaks, short OOM loops, long GC cycles,
or growth that started only recently may not pass these conservative thresholds.
No-pattern means no qualifying pattern in the supplied window, not proof of safety
or complete replica/OOM collection. Confirmation needs application/load context and
runtime diagnostics such as [heap profiles](https://go.dev/doc/diagnostics).
Comparing leak incidence across historical releases is left to callers; one result
only evaluates its selected release segment.

## Consumers

- [`dashboard-api-service`](https://github.com/kedify/dashboard-api-service)
  adapts stored Kedify telemetry or Prometheus-compatible results to normalized
  input.
- [`kedify/cli`](https://github.com/kedify/cli) links the same package for local
  and air-gapped analysis.

## Development

Run the tests with:

```sh
go test ./...
```

## License

Kedify-owned material is offered under the [Kedify Commercial Subscription
License 1.0](LICENSE) and [Public Source Addendum 1.0](PUBLIC_SOURCE_LICENSE).
This is source-available software. Production use requires an active Kedify
subscription covering Recommender, including when running locally or offline.
The terms permit source inspection, private builds and a 30-day evaluation;
subscribers may privately modify and compile covered source.

Include both Kedify texts and applicable third-party notices in distributions.
Submitted code requires a signed contribution assignment before acceptance.

### Decision traces and chart normalization

Resource analyses include an additive `decisionTrace` (version `1`) from detector
version `6`. It records the winning series/pod, aggregation method and source time,
previous-rollout attempts and rejections, and each request/limit calculation and
executed guard. Setting dispositions distinguish `recommended`, `retained`,
`disabled`, and `unavailable`. Numeric calculation values use the resource's native
units (CPU millicores, memory bytes); coefficients and relative changes are ratios.
Traces do not change sizing behavior or contain raw samples.

`analysis.NormalizeSamples(series, start, end)` exposes the same sample conversion
used by sizing, including CPU counter resets, duplicate handling, and timestamp
filtering. Chart consumers should use it before display-only downsampling; never
recompute recommendations from reduced chart data.
