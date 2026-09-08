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

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
