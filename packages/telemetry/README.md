# `@azx-pbc/telemetry`

Owns every OpenTelemetry SDK import for the platform ([ADR-0037](../../docs/adr/0037-platform-observability-otlp-boundary.md)
decision 3). Only the three `server.ts` boot seams (`apps/edge`, `apps/portal`,
`apps/egress`) import this package; everything from `buildApp()` inward imports the
dependency-free `@opentelemetry/api` facade and nothing else.

**The one rule that must not erode: OTLP is the only telemetry wire format any service
knows.** No vendor SDK name — `applicationinsights`, `@azure/monitor-*` — appears
anywhere outside `infra/azure`. The fact that a given deployment's OTLP destination
happens to be Application Insights is infrastructure knowledge, not code.

## Usage

```ts
import { startTelemetry } from "@azx-pbc/telemetry";
import { SERVICE_NAME } from "./app.js";

const telemetry = startTelemetry(SERVICE_NAME);

// ... construct pools, call buildApp(), etc.

app.addHook("onClose", async () => {
  await telemetry.shutdown();
});
```

Call `startTelemetry` early — before pools and `buildApp()` — the same seam `server.ts`
already owns for every other piece of impure boot setup.

## Inert by default

`startTelemetry` returns a no-op handle — constructing no SDK, provider, or exporter —
whenever any of the following holds (ADR-0037 decision 5), mirroring `loggerOption()`'s
test-quiet branch in `packages/shared/src/logging.ts`:

- `NODE_ENV=test`
- `OTEL_SDK_DISABLED` is `"1"` or `"true"`
- no `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces/metrics-specific override) is set

This is provable, not just "points nowhere": nothing else in the repo would catch a
service that silently started exporting from the test suite, which is the same gap
`loggerOption`'s test-quiet branch exists to close.

When telemetry is configured, exporter/SDK-internal failures log at `warn` and are
dropped — a dead or hanging collector never changes a response status or body, and spans
flush through a `BatchSpanProcessor` (bounded queue, async flush) so a slow collector
can never block the event loop (ADR-0003).

## What this package does NOT do yet

This is a foundation scaffold. Deliberately absent, each its own follow-up:

- **No spans or metrics are recorded anywhere.** No handler is instrumented.
- **No span-attribute redaction.** ADR-0037 decision 6 extends the `packages/shared/src/logging.ts`
  redaction guarantee to span attributes — security-sensitive, separate PR/review.
- **No trace-context propagation** edge → egress (decision 7).
- **No OTel log bridge** — logs stay on pino → stdout for now (decision 9).

## See also

[ADR-0037](../../docs/adr/0037-platform-observability-otlp-boundary.md) for the full
decision record.
