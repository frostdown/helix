import { readFileSync } from "node:fs";
import { startTelemetry } from "@azx-pbc/telemetry";
import { SERVICE_NAME, buildApp } from "./app.js";
import { loadConfig, publicOrigin } from "./config.js";
import { createBlobReader } from "./blob/client.js";
import { LiveRegistry, type RegistryLogger } from "./registry/listener.js";
import { OpenIdConnectClient } from "./auth/oidc.js";
import { PgSessionStore, startSessionSweeper } from "./auth/sessions.js";
import { anthropicVendor, openAiVendor, type LlmProvider } from "./gateway/provider.js";
import { EgressLlmProvider } from "./gateway/egressLlmProvider.js";
import { RoutingLlmProvider } from "./gateway/routingLlmProvider.js";
import { HttpEgressProvider, type EgressProvider } from "./gateway/egressProvider.js";
import { deriveInstructionKey } from "./gateway/instruction.js";
import { PgUsageStore, type UsageStore } from "./gateway/usage.js";
import { PgAppDataStore, type AppDataStore } from "./gateway/data.js";
import { IpRateLimiter } from "./gateway/ipRateLimiter.js";
import { LoginThrottle } from "./auth/loginThrottle.js";
import { PgCounterStore } from "./gateway/counterStore.js";
import { PgCspReportStore } from "./serving/cspReport.js";
import type { PoolClientErrorPhase } from "./db/pool.js";

/**
 * Dev convenience: load `apps/edge/.env.local` (gitignored) into process.env
 * before config. As a developer-local override file (the `.env.local`
 * convention), its values WIN over the inherited environment — so you can
 * repoint the edge at a different IdP (e.g. real Entra, via certificate auth)
 * without editing the committed devcontainer env. Absent in prod/CI (it's
 * gitignored), where this is a no-op. Hand-rolled (no `dotenv`): the edge is
 * dependency-minimal (project plan §6).
 */
function loadDotEnvLocal(): void {
  let text: string;
  try {
    text = readFileSync(new URL("../.env.local", import.meta.url), "utf8");
  } catch {
    return; // absent is normal (prod, CI)
  }
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadDotEnvLocal();

const telemetry = startTelemetry(SERVICE_NAME);

// Bind 0.0.0.0 — inside the container the port is reached across the Docker
// network / forwarded to the host.
const port = Number(process.env.EDGE_PORT ?? process.env.PORT ?? 8080);
const host = process.env.HOST ?? "0.0.0.0";

const config = loadConfig();
const blob = createBlobReader(config.blob);

// Dev TLS termination (mkcert): `__Host-` cookies require Secure, so the real
// cookie model must run locally (project plan §3). Prod stays plain HTTP
// behind Azure ingress and leaves `tls` unset.
let https: { cert: Buffer; key: Buffer } | null = null;
if (config.tls) {
  try {
    https = {
      cert: readFileSync(config.tls.certFile),
      key: readFileSync(config.tls.keyFile),
    };
  } catch (err) {
    throw new Error(
      "EDGE_TLS_* points at unreadable files — re-run .devcontainer/post-create.sh " +
        "to generate the mkcert certs",
      { cause: err },
    );
  }
}

// The registry logs through the app's logger, but buildApp needs the registry
// — bridge the cycle with a late-bound reference. Safe for the ADR-0025
// first-failure `error` line: buildApp and the rebind below both run before
// `registry.start()` triggers the first load, so no failure hits the no-op stub.
const logRef: { current: RegistryLogger } = {
  current: { info: () => {}, warn: () => {}, error: () => {} },
};
/**
 * One reporting sink for every pool the edge builds. Stores are constructed
 * before `buildApp` creates the Fastify logger, so this rides the same
 * late-bound `logRef`. `warn`, not `error`: a checked-out drop already fails its
 * own request through that request's error log, and an `error` per pool on every
 * DB restart would drown the ADR-0025 staleness ladder.
 */
const onClientError = (err: unknown, ctx: { phase: PoolClientErrorPhase; label: string }): void => {
  logRef.current.warn(
    { event: "db.pool_client_error", pool: ctx.label, phase: ctx.phase, err },
    `pooled DB client dropped (${ctx.label}, ${ctx.phase})`,
  );
};
const registry = new LiveRegistry({
  databaseUrl: config.databaseUrl,
  reconcileIntervalMs: config.reconcileIntervalMs,
  statementTimeoutMs: config.statementTimeoutMs,
  log: {
    info: (obj, msg) => logRef.current.info(obj, msg),
    warn: (obj, msg) => logRef.current.warn(obj, msg),
    error: (obj, msg) => logRef.current.error(obj, msg),
  },
});

// Auth stack — only when the config block is present (fail-closed otherwise).
const sessions = config.auth
  ? new PgSessionStore(config.databaseUrl, {
      statementTimeoutMs: config.statementTimeoutMs,
      onClientError,
    })
  : null;
const oidc = config.auth
  ? new OpenIdConnectClient(config.auth, `${publicOrigin(config, "auth")}/callback`, {
      // The OIDC client's logger seam is narrower (a bare message on info); the
      // late-bound ref underneath is the registry's, so adapt rather than widen.
      info: (msg) => logRef.current.info({}, msg),
      warn: (obj, msg) => logRef.current.warn({ ...obj }, msg),
    })
  : null;

// LLM gateway (M4). The metering/budget ledger comes up with the auth stack
// (the capability requires a session); the vendor provider only when a key is
// configured (otherwise the capability 503s — fail-closed, like auth).
const usage: UsageStore | null = config.auth
  ? new PgUsageStore(config.databaseUrl, {
      statementTimeoutMs: config.statementTimeoutMs,
      onClientError,
    })
  : null;
// App-data capability (app-data design §3): comes up with the auth stack, like
// the meter — every data verb is gated and caller-scoped.
const appData: AppDataStore | null = config.auth
  ? new PgAppDataStore(config.databaseUrl, {
      statementTimeoutMs: config.statementTimeoutMs,
      onClientError,
    })
  : null;
// CSP report sink (§6.2) — append-only, no auth needed; always on (the edge
// always has a DB connection for the registry).
const cspReports = new PgCspReportStore(config.databaseUrl, {
  statementTimeoutMs: config.statementTimeoutMs,
  onClientError,
});
// Shared, PG-backed counter behind both abuse controls (issue #13): the anon
// per-IP gateway limiter and the shared-password login throttle. One store +
// namespaced keys means the limits hold across the horizontally-scaled fleet
// (not N×-per-replica) and one sweep GCs both. Owned here so it can be swept and
// closed; passed into the app.
const counterStore = new PgCounterStore(config.databaseUrl, {
  statementTimeoutMs: config.statementTimeoutMs,
  onClientError,
});
const anonRateLimiter = new IpRateLimiter(config.anonRateLimit, counterStore);
const loginThrottle = new LoginThrottle(counterStore);

// Fetch-proxy + LLM (M4.5): the edge is the policy plane and forwards authorized
// calls to azx-egress over the EgressProvider seam. The capability is enabled
// only when both the egress URL and the shared instruction secret are present
// (otherwise /_api/fetch and the egress LLM path 503 — fail-closed).
const egress: EgressProvider | null = config.fetch.egressUrl
  ? new HttpEgressProvider(config.fetch.egressUrl, { timeoutMs: config.fetch.timeoutMs })
  : null;
const instructionKey = config.fetch.instructionSecret
  ? deriveInstructionKey(config.fetch.instructionSecret)
  : null;

// LLM provider selection (secrets design §1). Two states only — the edge never
// holds the vendor key:
//  1. egress configured → route the vendor call through egress; the key is a
//     `platform` secret egress injects, so the edge never holds it.
//  2. egress unconfigured → null; the capability 503s (fail-closed, like auth).
// There is deliberately no direct edge→Anthropic path: the edge holding the key
// would violate the containment model (ADR-0008, issue #10). Local dev runs the
// canonical path via `pnpm dev:egress`.
// Both vendors route through egress behind the RoutingLlmProvider, which picks
// the upstream per request from the model's catalog `provider` field. Both are
// wired whenever egress is up; a vendor is "enabled" by seeding its `platform`
// key secret. The OpenAI-compatible upstream points at api.openai.com today or a
// Warden URL later (config only).
const llmProvider: LlmProvider | null =
  egress && instructionKey
    ? new RoutingLlmProvider({
        anthropic: new EgressLlmProvider(
          anthropicVendor({
            endpoint: config.llm.endpoint,
            anthropicVersion: config.llm.anthropicVersion,
            connection: config.llm.connection,
          }),
          egress,
          instructionKey,
        ),
        openai: new EgressLlmProvider(openAiVendor(config.llm.openai), egress, instructionKey),
      })
    : null;

const app = buildApp({
  config,
  registry,
  blob,
  sessions,
  oidc,
  llmProvider,
  usage,
  appData,
  egress,
  instructionKey,
  cspReports,
  anonRateLimiter,
  loginThrottle,
  https,
});
logRef.current = {
  info: (obj, msg) => app.log.info(obj, msg),
  warn: (obj, msg) => app.log.warn(obj, msg),
  error: (obj, msg) => app.log.error(obj, msg),
};
const sweeper = sessions
  ? startSessionSweeper(sessions, {
      log: {
        info: (msg) => app.log.info(msg),
        warn: (obj, msg) => app.log.warn(obj, msg),
      },
    })
  : null;
// GC elapsed rate_counters rows so the table can't grow under a flood of
// distinct source IPs. Covers BOTH the anon limiter and the login throttle
// (shared store), so it runs regardless of whether the anon limiter is enabled —
// the login throttle always is. `unref` so it never holds the process open.
const counterSweepMs = config.anonRateLimit.windowMs > 0 ? config.anonRateLimit.windowMs : 60_000;
const counterSweep = setInterval(() => {
  void counterStore
    .sweep()
    .catch((err: unknown) => app.log.warn({ err }, "rate_counters sweep failed"));
}, counterSweepMs);
counterSweep.unref();
app.addHook("onClose", async () => {
  sweeper?.stop();
  clearInterval(counterSweep);
  oidc?.stop();
  await registry.stop();
  await sessions?.close();
  await usage?.close();
  await appData?.close();
  await egress?.close();
  await cspReports.close();
  await llmProvider?.close();
  await counterStore.close();
  await blob.close();
  // Last: a hung collector's final flush is bounded by the exporter timeout, and
  // must not stall the pool/timer teardown above it (ADR-0037 decision 5).
  await telemetry.shutdown();
});

try {
  // First load attempt completes before we accept traffic; a down DB logs and
  // retries rather than blocking boot (LiveRegistry.start never throws, and
  // neither does OIDC discovery — auth routes 503 until it lands).
  await registry.start();
  await oidc?.start();
  await app.listen({ port, host });
  app.log.info(
    {
      baseDomain: config.baseDomain,
      allowUnauthenticated: config.allowUnauthenticated,
      tls: https !== null,
    },
    "azx-edge serving",
  );
  if (config.allowUnauthenticated) {
    app.log.warn("EDGE_DEV_ALLOW_UNAUTHENTICATED is set — app content is served without sessions");
  }
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
