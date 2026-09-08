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

Callers are responsible for collecting and aggregating observations. In
particular, CPU `max` or `percentile` selection happens in the caller's metrics
query or snapshot adapter; the normalized `aggregatedUsage` value must match the
supplied policy.

Input/output schema versions describe the data shape. The detector and effective
policy versions preserve recommendation identity across callers. Consumers should
pin a released module version and reject unsupported schemas instead of converting
legacy input.

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
