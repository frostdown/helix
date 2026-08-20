import { metrics, trace } from "@opentelemetry/api";
import { describe, expect, it } from "vitest";
import { startTelemetry } from "./index.js";

/**
 * Inertness has to be asserted on the *observable side effect*, not on the shape
 * of the returned handle: a `startTelemetry` that constructed a live provider and
 * exporter would still hand back an object with a `shutdown` function. What proves
 * it stayed inert is that nothing got registered on the API globals (ADR-0037
 * decisions 5 and 10).
 *
 * The two signals need different probes, which is worth stating because the
 * symmetric-looking version of this check is silently vacuous.
 * `trace.getTracerProvider()` returns the same `ProxyTracerProvider` singleton
 * before and after registration — only its delegate swaps — so comparing that
 * identity asserts nothing. A span's `isRecording()` is the real discriminator:
 * false under the no-op provider, true once a real one is registered.
 * `metrics.getMeterProvider()` has no proxy in front of it, so there the identity
 * comparison is meaningful.
 */
function expectNoProvidersRegistered(run: () => void): void {
  const meterBefore = metrics.getMeterProvider();
  expect(trace.getTracer("inertness-probe").startSpan("probe").isRecording()).toBe(false);
  run();
  expect(trace.getTracer("inertness-probe").startSpan("probe").isRecording()).toBe(false);
  expect(metrics.getMeterProvider()).toBe(meterBefore);
}

/** Set env for the duration of `run`, restoring exactly on the way out. */
function withEnv(patch: Record<string, string | undefined>, run: () => void): void {
  const saved = new Map<string, string | undefined>();
  for (const key of Object.keys(patch)) saved.set(key, process.env[key]);
  try {
    for (const [key, value] of Object.entries(patch)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    run();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

const NO_ENDPOINT = {
  OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: undefined,
  OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: undefined,
};

describe("startTelemetry", () => {
  it("registers nothing under NODE_ENV=test (ambient in this suite)", () => {
    expect(process.env.NODE_ENV).toBe("test");
    expectNoProvidersRegistered(() => {
      const handle = startTelemetry("azx-edge");
      expect(typeof handle.shutdown).toBe("function");
    });
  });

  it("registers nothing under NODE_ENV=test even with an endpoint configured", () => {
    withEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318" }, () => {
      expectNoProvidersRegistered(() => startTelemetry("azx-edge"));
    });
  });

  it("registers nothing when OTEL_SDK_DISABLED=1 outside test", () => {
    withEnv(
      {
        NODE_ENV: "production",
        OTEL_SDK_DISABLED: "1",
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      },
      () => {
        expectNoProvidersRegistered(() => startTelemetry("azx-edge"));
      },
    );
  });

  it("registers nothing when no OTLP endpoint is configured outside test", () => {
    withEnv({ NODE_ENV: "production", OTEL_SDK_DISABLED: undefined, ...NO_ENDPOINT }, () => {
      expectNoProvidersRegistered(() => startTelemetry("azx-egress"));
    });
  });

  it("shutdown() on an inert handle resolves without throwing", async () => {
    const handle = startTelemetry("azx-edge");
    await expect(handle.shutdown()).resolves.toBeUndefined();
  });

  it("shutdown() on an inert handle is safe to call twice", async () => {
    const handle = startTelemetry("azx-portal");
    await handle.shutdown();
    await expect(handle.shutdown()).resolves.toBeUndefined();
  });
});
