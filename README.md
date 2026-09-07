# Kedify Recommender

This private Go module contains the pure resource recommendation calculations shared
by Kedify services. It does not query metrics, call Kubernetes, serve HTTP, or store
recommendations.

The `analysis` package accepts normalized per-container observations and a policy. It
returns deterministic CPU and memory request/limit recommendations together with the
evidence and data quality used to produce them.

Input/output schema versions describe the wire shape. The separate detector and
effective-policy versions preserve recommendation identity across callers.

```go
output, err := analysis.Analyze(snapshot, policy)
```

Callers are responsible for collecting and aggregating observations. In particular,
CPU `max` or `percentile` selection happens in the caller's metrics query or snapshot
adapter; the normalized `aggregatedUsage` value must match the supplied policy.

## Distribution

- `dashboard-api-service` imports this module and adapts stored Kedify telemetry or
  Prometheus-compatible results to the normalized input.
- `kedify-analyzer` packages the engine as a separate, network-free executable.
- The public [`kedify/cli`](https://github.com/kedify/cli) does not import this
  private module. Local analysis integration is tracked by
  [`kedify/agent#618`](https://github.com/kedify/agent/issues/618) and
  [`kedify/cli#14`](https://github.com/kedify/cli/issues/14).

## Local analyzer

Build and invoke the executable with a single JSON request on standard input:

```sh
go build -o kedify-analyzer ./cmd/kedify-analyzer
kedify-analyzer < request.json > response.json
```

Diagnostics are written to standard error; standard output contains only the JSON
response. The current request contract is:

```json
{
  "protocolVersion": "kedify-analyzer/v1",
  "input": {
    "schemaVersion": "resource-analysis-input/v1",
    "observedIntervalHours": 24,
    "containers": []
  },
  "policy": {}
}
```

The response contains `protocolVersion`, `analyzerVersion`, `engineVersion`,
`inputSchemaVersion`, `outputSchemaVersion`, and the engine `output`. Only the exact
`kedify-analyzer/v1` protocol is accepted. The engine validates its input schema and
policy; there is no compatibility conversion in the executable. CPU
`aggregatedUsage` must already reflect the policy's `max` or `percentile` selection.
Requests larger than 16 MiB are rejected before decoding.

Exit codes are stable for this protocol:

| Code | Meaning |
| ---: | --- |
| `0` | Analysis completed and a response was written. |
| `1` | The analyzer could not read its request or write its response. |
| `2` | The request, protocol, schema, policy, or normalized input is invalid. |

Release archives include the following executables:

- Linux: `amd64`, `arm64`
- macOS: `amd64`, `arm64`
- Windows: `amd64`

Consumers should prefer an explicitly configured analyzer path, then a binary next
to the consuming executable, and finally `kedify-analyzer` (`kedify-analyzer.exe`
on Windows) on `PATH`. They must validate the returned protocol, engine, and schema
versions they support. Public CLI discovery and invocation are implemented separately
in [`kedify/cli#14`](https://github.com/kedify/cli/issues/14).

For an air-gapped environment, download the matching platform archive and its
`kedify-analyzer_<version>_checksums.txt` file in advance, verify the SHA-256 checksum,
and copy the extracted executable to the configured location. The analyzer performs
no network access and never downloads or updates itself.
