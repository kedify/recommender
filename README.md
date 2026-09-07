# Kedify Recommender

This private Go module contains the pure resource recommendation calculations shared
by Kedify services. It does not query metrics, call Kubernetes, serve HTTP, or store
recommendations.

The `analysis` package accepts normalized per-container observations and a policy. It
returns deterministic CPU and memory request/limit recommendations together with the
evidence and data quality used to produce them.

```go
output, err := analysis.Analyze(snapshot, policy)
```

Callers are responsible for collecting and aggregating observations. In particular,
CPU `max` or `percentile` selection happens in the caller's metrics query or snapshot
adapter; the normalized `aggregatedUsage` value must match the supplied policy.

## Distribution

- `dashboard-api-service` imports this module and adapts stored Kedify telemetry or
  Prometheus-compatible results to the normalized input.
- Private offline components may import the same module.
- The public [`kedify/cli`](https://github.com/kedify/cli) remains an API/results
  client and does not embed this private engine.
- Offline packaging is tracked by
  [`kedify/agent#618`](https://github.com/kedify/agent/issues/618).

The module is a library only. The previous placeholder binary and image deployment
have been removed.
