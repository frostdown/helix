import { describe, expect, it } from "vitest";
import { resolveTelemetryConfig } from "./config.js";

describe("resolveTelemetryConfig", () => {
  it("is inert under NODE_ENV=test, even with an endpoint set", () => {
    expect(
      resolveTelemetryConfig("azx-edge", {
        NODE_ENV: "test",
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      }),
    ).toBeNull();
  });

  it("is inert when OTEL_SDK_DISABLED=1", () => {
    expect(
      resolveTelemetryConfig("azx-edge", {
        NODE_ENV: "production",
        OTEL_SDK_DISABLED: "1",
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      }),
    ).toBeNull();
  });

  it("is inert when OTEL_SDK_DISABLED=true (the other spec-valid value)", () => {
    expect(
      resolveTelemetryConfig("azx-edge", {
        NODE_ENV: "production",
        OTEL_SDK_DISABLED: "true",
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      }),
    ).toBeNull();
  });

  it("is not disabled by an unrecognized OTEL_SDK_DISABLED value", () => {
    const config = resolveTelemetryConfig("azx-edge", {
      NODE_ENV: "production",
      OTEL_SDK_DISABLED: "yes",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
    });
    expect(config).not.toBeNull();
  });

  it("is inert with no endpoint configured", () => {
    expect(resolveTelemetryConfig("azx-edge", { NODE_ENV: "production" })).toBeNull();
  });

  it("is non-null when an endpoint is configured outside test", () => {
    const config = resolveTelemetryConfig("azx-edge", {
      NODE_ENV: "production",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
    });
    expect(config).toEqual({
      serviceName: "azx-edge",
      tracesEndpoint: "http://collector:4318",
      metricsEndpoint: "http://collector:4318",
    });
  });

  it("prefers the signal-specific endpoint override over the generic one", () => {
    const config = resolveTelemetryConfig("azx-portal", {
      NODE_ENV: "production",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://generic:4318",
      OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://traces-specific:4318",
      OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: "http://metrics-specific:4318",
    });
    expect(config?.tracesEndpoint).toBe("http://traces-specific:4318");
    expect(config?.metricsEndpoint).toBe("http://metrics-specific:4318");
  });

  it("uses the traces-specific endpoint for metrics too when no metrics override is set", () => {
    const config = resolveTelemetryConfig("azx-egress", {
      NODE_ENV: "production",
      OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://traces-only:4318",
    });
    expect(config?.tracesEndpoint).toBe("http://traces-only:4318");
    expect(config?.metricsEndpoint).toBe("http://traces-only:4318");
  });

  it("resolves against real process.env by default — the one case touching global state", () => {
    const saved = {
      NODE_ENV: process.env.NODE_ENV,
      OTEL_SDK_DISABLED: process.env.OTEL_SDK_DISABLED,
    };
    try {
      process.env.NODE_ENV = "test";
      expect(resolveTelemetryConfig("azx-edge")).toBeNull();
    } finally {
      if (saved.NODE_ENV === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = saved.NODE_ENV;
      if (saved.OTEL_SDK_DISABLED === undefined) delete process.env.OTEL_SDK_DISABLED;
      else process.env.OTEL_SDK_DISABLED = saved.OTEL_SDK_DISABLED;
    }
  });
});
