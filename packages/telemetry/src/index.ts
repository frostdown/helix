import { DiagLogLevel, type DiagLogger, diag, metrics } from "@opentelemetry/api";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { MeterProvider, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { BatchSpanProcessor, NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { ATTR_SERVICE_NAME } from "@opentelemetry/semantic-conventions";
import { resolveTelemetryConfig } from "./config.js";

export interface TelemetryHandle {
  /** Flush and tear down. Resolves even when telemetry was never started. */
  shutdown(): Promise<void>;
}

const NOOP_HANDLE: TelemetryHandle = {
  shutdown: async () => {},
};

/** Routes exporter/SDK-internal failures to `warn`, never a throw (decision 5). */
const warnOnlyDiagLogger: DiagLogger = {
  error: (...args) => console.warn(...args),
  warn: (...args) => console.warn(...args),
  info: () => {},
  debug: () => {},
  verbose: () => {},
};

/**
 * Boot-time telemetry setup (ADR-0037 decisions 3 & 5). Call once, early in a
 * service's `server.ts` — before pools and `buildApp()` — the same seam
 * `server.ts` already owns for every other piece of impure setup. Only the
 * three `server.ts` files should import this package; everything from
 * `buildApp()` inward imports `@opentelemetry/api` and nothing else.
 *
 * Returns a no-op handle — constructing no SDK, provider, or exporter — when
 * `NODE_ENV=test`, when `OTEL_SDK_DISABLED` is `"1"`/`"true"`, or when no OTLP
 * endpoint is configured. That inertness must be provable, not just "points
 * nowhere": nothing else catches a service that silently starts exporting from
 * the test suite.
 */
export function startTelemetry(serviceName: string): TelemetryHandle {
  const config = resolveTelemetryConfig(serviceName);
  if (!config) return NOOP_HANDLE;

  // `startTelemetry` runs before `buildApp()`, so no Fastify logger exists yet
  // at this call site (the same constraint apps/edge/src/devGateway/server.ts
  // solves with bare `console.error`). WARN filters SDK-internal INFO chatter;
  // a dead/hanging collector logs here and never throws into a handler.
  diag.setLogger(warnOnlyDiagLogger, DiagLogLevel.WARN);

  const resource = resourceFromAttributes({ [ATTR_SERVICE_NAME]: config.serviceName });

  const tracerProvider = new NodeTracerProvider({
    resource,
    // BatchSpanProcessor only — bounded queue, async flush. Never a
    // Simple/synchronous processor: ADR-0003's never-block-the-event-loop rule.
    spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter({ url: config.tracesEndpoint }))],
  });
  // `register()` rather than `trace.setGlobalTracerProvider()`: only the former
  // installs the AsyncLocalStorageContextManager, without which `context.active()`
  // is always ROOT and every hand-placed span in the follow-ups becomes a root
  // instead of a child. `propagator: null` explicitly declines to install a global
  // W3C propagator — the edge must not continue a trace from an app-user request
  // (ADR-0037 decision 7), and the inward edge -> egress hop is its own PR.
  tracerProvider.register({ propagator: null });

  const meterProvider = new MeterProvider({
    resource,
    readers: [
      new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: config.metricsEndpoint }),
      }),
    ],
  });
  metrics.setGlobalMeterProvider(meterProvider);

  return {
    shutdown: async () => {
      // Independently caught: a failed flush must never throw out of a
      // service's onClose hook and block the rest of that hook's teardown.
      await tracerProvider
        .shutdown()
        .catch((err: unknown) => console.warn("telemetry: trace provider shutdown failed", err));
      await meterProvider
        .shutdown()
        .catch((err: unknown) => console.warn("telemetry: meter provider shutdown failed", err));
    },
  };
}
