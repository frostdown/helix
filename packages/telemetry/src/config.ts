/**
 * Whether OTel telemetry is configured for this process, resolved once at
 * `startTelemetry()` call time (ADR-0037 decisions 3 & 5).
 *
 * Mirrors `loggerOption()`'s test-quiet branch (`packages/shared/src/logging.ts`):
 * `env` is a default parameter, never read internally via a bare `process.env`
 * reference, so every branch is directly assertable without mutating global
 * state. Exported as a function rather than inlined at the `startTelemetry` call
 * site for the same reason `loggerOption` is — otherwise nothing catches a
 * service that silently starts exporting from the test suite.
 */
export interface TelemetryConfig {
  readonly serviceName: string;
  readonly tracesEndpoint: string;
  readonly metricsEndpoint: string;
}

/**
 * `null` when: `NODE_ENV=test`; `OTEL_SDK_DISABLED` is `"1"` or `"true"` (the
 * two spec-valid values); or no OTLP endpoint is configured. Otherwise a config
 * with the traces/metrics endpoints resolved from their signal-specific
 * `OTEL_EXPORTER_OTLP_*_ENDPOINT` override, falling back to the generic
 * `OTEL_EXPORTER_OTLP_ENDPOINT`.
 */
export function resolveTelemetryConfig(
  serviceName: string,
  env: NodeJS.ProcessEnv = process.env,
): TelemetryConfig | null {
  if (env.NODE_ENV === "test") return null;
  if (env.OTEL_SDK_DISABLED === "1" || env.OTEL_SDK_DISABLED === "true") return null;

  const endpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT;
  const tracesEndpoint = env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT ?? endpoint;
  if (!tracesEndpoint) return null;
  const metricsEndpoint = env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT ?? endpoint ?? tracesEndpoint;

  return { serviceName, tracesEndpoint, metricsEndpoint };
}
