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
input; results use output schema v3 and resource detector version 7. Consumers
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
and inventory checks remain current. Historical pod
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
and requests-only guards still apply. In particular, introducing an unset
limit still requires safe inventory evidence. Numeric signals that omit
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
