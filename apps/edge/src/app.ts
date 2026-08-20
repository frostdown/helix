import Fastify, { type FastifyInstance } from "fastify";
import { HealthStatusSchema, isValidServiceWorkerScope, worstHealthState } from "@azx-pbc/shared";
import { loggerOption } from "@azx-pbc/shared/logging";
import type { EdgeConfig } from "./config.js";
import type { BlobReader } from "./blob/client.js";
import type { RegistryFreshnessReader, RegistryReader } from "./registry/projection.js";
import { registryFreshnessCheck } from "./registry/health.js";
import { classifyHost, type HostClass } from "./routing/hosts.js";
import { makeAssetHandler } from "./serving/assets.js";
import { sendMethodNotAllowed, sendNotFound, sendUnavailable } from "./errors.js";
import { normalizeRequestPath } from "./serving/paths.js";
import { deriveAuthKeys } from "./auth/secrets.js";
import type { OidcClient } from "./auth/oidc.js";
import type { SessionStore } from "./auth/sessions.js";
import { makeCallbackHandler, makeStartHandler } from "./auth/routes/authHost.js";
import {
  makeAuthCompleteHandler,
  makeLogoutHandler,
  makeMeHandler,
} from "./auth/routes/appHost.js";
import {
  makePasswordLoginPageHandler,
  makePasswordLoginSubmitHandler,
} from "./auth/routes/passwordLogin.js";
import { LoginThrottle } from "./auth/loginThrottle.js";
import { IpRateLimiter } from "./gateway/ipRateLimiter.js";
import { InMemoryCounterStore } from "./gateway/counterStore.js";
import { makeCallerResolver, makeSessionGate } from "./auth/gate.js";
import { makeSameOriginCheck } from "./auth/validate.js";
import { makeLlmHandler } from "./gateway/llm.js";
import { openAiCodec } from "./gateway/openaiCodec.js";
import { makeOpenAiModelsHandler } from "./gateway/openaiModels.js";
import { makeDataHandlers } from "./gateway/data-handler.js";
import { makeFetchHandler } from "./gateway/fetch.js";
import type { EgressProvider } from "./gateway/egressProvider.js";
import { makeCspReportHandler, type CspReportStore } from "./serving/cspReport.js";
import { CSP_REPORT_PATH, buildAppCsp } from "./serving/csp.js";
import {
  SW_PATH,
  SW_SCOPE_PARAM,
  buildServiceWorkerScript,
  buildTombstoneScript,
} from "./serving/serviceWorker.js";
import type { LlmProvider } from "./gateway/provider.js";
import type { UsageStore } from "./gateway/usage.js";
import type { AppDataStore } from "./gateway/data.js";

/**
 * azx-edge — the data plane (architecture §3). Stateless; terminates all
 * `*.azx.helix.azxlabs.io` traffic. **Hard rule: dependency-minimal** — every npm
 * package here is code inside the trusted path, so additions need review
 * (project plan §6).
 *
 * M2: host routing, registry projection, asset streaming, baseline CSP.
 * Sessions/OIDC (M3) and the `/_api/*` gateway (M4) come later.
 */
export const SERVICE_NAME = "azx-edge";

export interface EdgeDeps {
  config: EdgeConfig;
  /** `/health` reads `freshness()`; every other consumer only routes on `getApp`. */
  registry: RegistryReader & RegistryFreshnessReader;
  blob: BlobReader;
  /** Session persistence; required for the auth routes to exist. */
  sessions?: SessionStore | null;
  /** IdP client; required for the auth routes to exist. */
  oidc?: OidcClient | null;
  /** LLM vendor provider (M4); null = no vendor key, capability 503s. */
  llmProvider?: LlmProvider | null;
  /** Gateway metering/budget ledger (M4); null disables the LLM capability. */
  usage?: UsageStore | null;
  /** App-data store (M4/M5); null = the data capability 503s. */
  appData?: AppDataStore | null;
  /** Egress client for the fetch-proxy (M4.5); null = the capability 503s. */
  egress?: EgressProvider | null;
  /** HKDF-derived instruction signing key; null = the fetch capability 503s. */
  instructionKey?: Buffer | null;
  /** CSP-violation report sink (§6.2); null = accept-and-drop. */
  cspReports?: CspReportStore | null;
  /** Shared-password login throttle; tests inject a low-threshold one. */
  loginThrottle?: LoginThrottle | null;
  /** Anonymous-tier per-IP gateway limiter; tests inject a low-threshold one. */
  anonRateLimiter?: IpRateLimiter | null;
  /** Dev TLS material (server.ts reads the mkcert files); tests omit it. */
  https?: { cert: Buffer; key: Buffer } | null;
}

/**
 * Platform path namespaces on app hosts — never composed into blob keys.
 * Checked against BOTH the raw URL and the percent-decoded path the asset
 * handler will actually resolve (`/_api%2fme` decodes to `/_api/me` and must
 * be reserved too, not fall through to a blob named `_api/me`).
 */
function isReservedAppPath(rawUrl: string): boolean {
  const raw = rawUrl.split("?", 1)[0] ?? "";
  const decoded = normalizeRequestPath(rawUrl);
  for (const pathname of decoded === null ? [raw] : [raw, decoded]) {
    if (
      pathname === "/_auth" ||
      pathname.startsWith("/_auth/") ||
      pathname === "/_api" ||
      pathname.startsWith("/_api/") ||
      pathname === "/_helix" ||
      pathname.startsWith("/_helix/") ||
      pathname === "/_csp-report"
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Read one query value, collapsing Fastify's `string | string[]` for a repeated
 * key. A repeat is refused rather than resolved: `?scope=/app/&scope=/` is
 * someone probing, and picking either arm is a worse answer than none.
 */
function firstQueryValue(query: unknown, key: string): string | undefined {
  if (typeof query !== "object" || query === null) return undefined;
  const value = (query as Record<string, unknown>)[key];
  return typeof value === "string" ? value : undefined;
}

declare module "fastify" {
  interface FastifyRequest {
    /** Set once per request by the host-classification hook. */
    hostClass: HostClass;
    /**
     * Dev-gateway only (dev-mode §5.4): the request Origin the `DevTokenResolver`
     * validated against the token's allowlist, reflected back as
     * `Access-Control-Allow-Origin`. Never set on the edge (no CORS there).
     */
    devCorsOrigin?: string;
  }
}

export function buildApp(deps: EdgeDeps): FastifyInstance {
  const { config } = deps;
  // The https/http generics differ; the instance is used identically, so the
  // assertion keeps one return type rather than a generic explosion.
  const app = Fastify({
    // Quiet during tests; structured JSON logs otherwise, with the handoff
    // token / OIDC code / fetch-proxy target redacted out of the logged URL
    // (issue #20 — `@azx-pbc/shared/logging`).
    logger: loggerOption(),
    // How many proxy hops to trust for `req.ip` (the rate-limit / login-throttle
    // key). Default false = the socket peer. Behind Container Apps' Envoy ingress
    // that peer is the ingress, so per-client limits need EDGE_TRUST_PROXY set to
    // the real ingress hop count — verify against the live deployment before
    // relying on it (issue #13). A too-trusting value makes X-Forwarded-For
    // spoofable, so it is opt-in, not defaulted on.
    trustProxy: config.trustProxy,
    ...(deps.https ? { https: deps.https } : {}),
  }) as unknown as FastifyInstance;

  // Auth routes exist only when the whole auth stack is wired (config block +
  // session store + OIDC client); otherwise they fail closed below.
  const authRuntime =
    config.auth && deps.sessions && deps.oidc
      ? {
          config,
          auth: config.auth,
          keys: deriveAuthKeys(config.auth.secret),
          registry: deps.registry,
          sessions: deps.sessions,
          oidc: deps.oidc,
        }
      : null;
  const gate = authRuntime
    ? makeSessionGate({ config, auth: authRuntime.auth, sessions: authRuntime.sessions })
    : null;
  // The gateway keys identity off a Caller (authenticated session, or anon for
  // `public` apps — app-data design §6). The resolver wraps the gate with the
  // public-app short-circuit; asset serving keeps its own public bypass.
  const resolveCaller = gate ? makeCallerResolver(gate, config) : null;
  // Production CSRF check: exact same-origin. The dev-gateway swaps this seam
  // for an allowlist (dev-mode §5.4); here every gateway runtime gets the same.
  const checkOrigin = makeSameOriginCheck(config);
  // One limiter backs every public app's anonymous tier (app-data design §7).
  // server.ts injects PG-backed limiters (shared across replicas) + owns the
  // sweep; tests inject a low one. The fallback in-memory counter here keeps
  // single-process dev / tests working without a DB (both fallbacks share it —
  // keys are namespaced, so no collision).
  const fallbackCounters = new InMemoryCounterStore();
  const anonRateLimiter =
    deps.anonRateLimiter ?? new IpRateLimiter(config.anonRateLimit, fallbackCounters);
  const serveAsset = makeAssetHandler({ ...deps, gate });

  const handleStart = authRuntime ? makeStartHandler(authRuntime) : null;
  const handleCallback = authRuntime ? makeCallbackHandler(authRuntime) : null;
  const handleAuthComplete = authRuntime ? makeAuthCompleteHandler(authRuntime) : null;
  const appApiRuntime =
    authRuntime && gate
      ? { config, registry: deps.registry, sessions: authRuntime.sessions, gate }
      : null;
  const handleMe = appApiRuntime ? makeMeHandler(appApiRuntime) : null;
  const handleLogout = appApiRuntime ? makeLogoutHandler(appApiRuntime) : null;
  // The shared-password challenge (`password` visibility). Same-origin on the
  // app host — no auth host, no handoff — so it lives outside authRuntime's
  // OIDC surface. One throttle instance backs every app's login.
  const passwordLoginRuntime = authRuntime
    ? {
        config,
        auth: authRuntime.auth,
        registry: deps.registry,
        sessions: authRuntime.sessions,
        throttle: deps.loginThrottle ?? new LoginThrottle(fallbackCounters),
      }
    : null;
  const handleLoginPage = passwordLoginRuntime
    ? makePasswordLoginPageHandler(passwordLoginRuntime)
    : null;
  const handleLoginSubmit = passwordLoginRuntime
    ? makePasswordLoginSubmitHandler(passwordLoginRuntime)
    : null;
  // The LLM gateway needs a session (gate) to attribute calls; provider/usage
  // may still be null (no vendor key), in which case the handler returns 503.
  // The same runtime backs the native (`/_api/llm/chat`) and OpenAI-compatible
  // (`/_api/openai/v1/*`) surfaces — only the wire codec differs.
  const llmRuntime =
    appApiRuntime && resolveCaller
      ? {
          config,
          registry: deps.registry,
          resolveCaller,
          checkOrigin,
          anonLimiter: anonRateLimiter,
          provider: deps.llmProvider ?? null,
          usage: deps.usage ?? null,
        }
      : null;
  const handleLlmChat = llmRuntime ? makeLlmHandler(llmRuntime) : null;
  const handleOpenAiChat = llmRuntime ? makeLlmHandler(llmRuntime, openAiCodec) : null;
  const handleOpenAiModels = llmRuntime ? makeOpenAiModelsHandler(llmRuntime) : null;
  // The data gateway needs a caller (session, or anon on public apps); the
  // store may be null (capability 503s), like the LLM provider.
  const dataHandlers =
    appApiRuntime && resolveCaller
      ? makeDataHandlers({
          config,
          registry: deps.registry,
          resolveCaller,
          checkOrigin,
          anonLimiter: anonRateLimiter,
          store: deps.appData ?? null,
          usage: deps.usage ?? null,
        })
      : null;
  // The fetch-proxy needs a caller (session, or anon on public apps); egress +
  // instruction key + usage may be null, in which case the handler 503s — same
  // fail-closed shape as the LLM vendor key.
  const handleFetch =
    appApiRuntime && resolveCaller
      ? makeFetchHandler({
          config,
          registry: deps.registry,
          resolveCaller,
          checkOrigin,
          anonLimiter: anonRateLimiter,
          egress: deps.egress ?? null,
          usage: deps.usage ?? null,
          instructionKey: deps.instructionKey ?? null,
        })
      : null;
  // The CSP report sink is unauthenticated (browsers send no credentials with
  // report beacons) and always available — it only ever appends.
  const handleCspReport = makeCspReportHandler({
    registry: deps.registry,
    store: deps.cspReports ?? null,
  });

  // The two-router discipline (architecture §3, decision 12): every request
  // is classified by hostname exactly once, and the two worlds never mix —
  // platform handlers are unreachable on app hosts and vice versa. Explicit
  // dispatch instead of find-my-way host constraints: the fallback semantics
  // between constrained and unconstrained routes are non-obvious, and this
  // way the boundary is one readable hook.
  app.decorateRequest("hostClass");
  app.addHook("onRequest", async (req) => {
    req.hostClass = classifyHost(req.headers.host, config.baseDomain);
  });

  // The shared-password login form posts urlencoded. Hand-rolled parser (no
  // @fastify/formbody — dep-minimal rule): URLSearchParams into a flat object.
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_req, body, done) => {
      try {
        const out: Record<string, string> = {};
        for (const [k, v] of new URLSearchParams(body as string)) out[k] = v;
        done(null, out);
      } catch (err) {
        done(err as Error);
      }
    },
  );

  // CSP violation reports arrive as `application/csp-report` (report-uri) or
  // `application/reports+json` (Reporting-API) — both JSON bodies Fastify won't
  // parse by default.
  app.addContentTypeParser(
    ["application/csp-report", "application/reports+json"],
    { parseAs: "string" },
    (_req, body, done) => {
      try {
        done(null, body ? JSON.parse(body as string) : undefined);
      } catch (err) {
        done(err as Error);
      }
    },
  );

  app.route({
    method: ["GET", "HEAD"],
    url: "/health",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app") {
        // App hosts serve only app content — a deployed file named /health
        // (or the SPA fallback) answers, never the platform health JSON.
        await serveAsset(req, reply, req.hostClass.slug);
        return;
      }
      // Registry freshness is reported, never fatal: the response stays 200 in
      // every state. A non-200 here would let a liveness probe restart a replica
      // that is serving correctly from a stale copy — the serve-stale stance
      // (architecture §7) turned into the outage it exists to prevent (ADR-0025).
      const checks = [
        registryFreshnessCheck(deps.registry.freshness(), config.reconcileIntervalMs),
      ];
      reply.header("cache-control", "no-store"); // a degraded body must not be cached
      return HealthStatusSchema.parse({
        status: worstHealthState(checks.map((c) => c.status)),
        service: SERVICE_NAME,
        uptime: process.uptime(),
        checks,
      });
    },
  });

  // Appendix A steps 1–7 live on the auth host; on app hosts these are just
  // asset paths (an app may legitimately ship /start.html etc. — the asset
  // handler sees the same URL it always did).
  for (const [url, handler] of [
    ["/start", handleStart],
    ["/callback", handleCallback],
  ] as const) {
    app.route({
      method: "GET",
      url,
      handler: async (req, reply) => {
        if (req.hostClass.kind === "auth") {
          if (handler) {
            await handler(req, reply);
          } else {
            sendUnavailable(reply, "Sign-in is not configured on this edge.");
          }
          return;
        }
        if (req.hostClass.kind === "app") {
          await serveAsset(req, reply, req.hostClass.slug);
          return;
        }
        sendNotFound(reply);
      },
    });
  }

  // Shared-password challenge (`password` visibility), on app hosts only. GET
  // serves the login page; POST verifies and mints the session. Non-password
  // apps 404 inside the handler (no signal).
  app.route({
    method: "GET",
    url: "/_auth/login",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleLoginPage) {
        await handleLoginPage(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });
  app.route({
    method: "POST",
    url: "/_auth/login",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleLoginSubmit) {
        await handleLoginSubmit(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // Appendix A step 8: handoff redemption, on app hosts only.
  app.route({
    method: "GET",
    url: "/_auth/complete",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleAuthComplete) {
        await handleAuthComplete(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  app.route({
    method: "POST",
    url: "/_auth/logout",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleLogout) {
        await handleLogout(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // Appendix A.6: the one thing an app may ask about its user.
  app.route({
    method: "GET",
    url: "/_api/me",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleMe) {
        await handleMe(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // M4 gateway: the LLM capability (architecture §6.1). App hosts only.
  app.route({
    method: "POST",
    url: "/_api/llm/chat",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleLlmChat) {
        await handleLlmChat(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // OpenAI-compatible surface (same runtime + policy, OpenAI wire). An app points
  // its OpenAI client at `baseURL = <origin>/_api/openai/v1`; the `__Host-session`
  // cookie authenticates same-origin, so the SDK `apiKey` is ignored. App hosts only.
  app.route({
    method: "POST",
    url: "/_api/openai/v1/chat/completions",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleOpenAiChat) {
        await handleOpenAiChat(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });
  app.route({
    method: "GET",
    url: "/_api/openai/v1/models",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app" && handleOpenAiModels) {
        await handleOpenAiModels(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // M4/M5 gateway: the app-data capability (app-data design §5.1). App hosts
  // only. NOTE the deliberate absence of any collection read/list/delete verb —
  // §3.2's write-only property is enforced by the route table AND the store
  // type, and is covered by an adversarial test.
  for (const [method, url, name] of [
    ["PUT", "/_api/data/user/:key", "putUser"],
    ["GET", "/_api/data/user/:key", "getUser"],
    ["DELETE", "/_api/data/user/:key", "deleteUser"],
    ["GET", "/_api/data/user", "listUser"],
    ["POST", "/_api/data/collections/:name", "postCollection"],
    ["GET", "/_api/data/shared/:key", "getShared"],
    ["PUT", "/_api/data/shared/:key", "putShared"],
  ] as const) {
    app.route({
      method,
      url,
      handler: async (req, reply) => {
        if (req.hostClass.kind === "app" && dataHandlers) {
          await dataHandlers[name](req, reply, req.hostClass.slug);
          return;
        }
        sendNotFound(reply);
      },
    });
  }

  // M4.5 gateway: the fetch-proxy (fetch-proxy design §7). App hosts only.
  // Encapsulated so a passthrough body parser keeps `req.raw` streamable for
  // egress (the proxy re-streams arbitrary bodies; never buffer them) without
  // disturbing the JSON parsing the llm/data routes rely on.
  if (handleFetch) {
    void app.register((fetchScope, _opts, doneRegister) => {
      fetchScope.removeAllContentTypeParsers();
      fetchScope.addContentTypeParser("*", (_req, payload, done) => done(null, payload));
      fetchScope.route({
        method: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        url: "/_api/fetch/*",
        handler: async (req, reply) => {
          if (req.hostClass.kind === "app") {
            await handleFetch(req, reply, req.hostClass.slug);
            return;
          }
          sendNotFound(reply);
        },
      });
      doneRegister();
    });
  }

  // CSP violation sink (§6.2): the app's `report-uri` posts here, same-origin.
  // App hosts only; the report is appended (or dropped) and always 204s.
  app.route({
    method: "POST",
    url: CSP_REPORT_PATH,
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app") {
        await handleCspReport(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // ADR-0035: the offline capability's platform-owned service worker. It is
  // **ungated** — a session gate here would 302 an expired-session update check
  // to the auth host, and a redirect during a worker script fetch is a
  // spec-level error, so the update would fail silently and a revoked worker
  // would stay installed. The script carries no app content.
  //
  // It is also the *only* `/_helix/` script route left. The fetch shim and the
  // worker's page-side registration used to be served from here too; both are
  // now inlined into the document at serve time (`serving/shim.ts`), because
  // `/_helix/*` is deliberately unprecachable and a `<script src>` under it is
  // exactly what an offline cold boot cannot load. A worker script has to be a
  // URL, so this one stays.
  app.route({
    method: ["GET", "HEAD"],
    url: SW_PATH,
    handler: async (req, reply) => {
      if (req.hostClass.kind !== "app") {
        sendNotFound(reply);
        return;
      }
      // A registry blip must never reach the tombstone below. Serving one is
      // destructive and irreversible client-side — it deletes every `helix:*`
      // cache and unregisters — so a fleet restart while Postgres is briefly
      // unreachable would wipe offline support across every device, exactly
      // when the platform is least healthy. A failed update check is strictly
      // better: it leaves the working worker installed. Same stance as
      // `assetHandler`, which 503s before the first load succeeds.
      if (!deps.registry.isLoaded()) {
        sendUnavailable(reply, "Registry unavailable; try again shortly.");
        return;
      }

      const entry = deps.registry.getApp(req.hostClass.slug);
      const grantedScope = entry && !entry.archived ? entry.offline?.scope : undefined;

      // A promote in flight (row present, nothing live) is a transient state,
      // not a revocation — 503 rather than unregister the fleet over a race.
      if (entry && grantedScope !== undefined && !entry.blobPrefix) {
        sendUnavailable(reply, "No live version; try again shortly.");
        return;
      }

      // The scope the *registration* claims, echoed from the script URL. Never
      // trusted: it only ever becomes a header after passing the same validator
      // the manifest field does, so it can be neither root, nor a `_` platform
      // namespace, nor a header-injection payload.
      const claimed = firstQueryValue(req.query, SW_SCOPE_PARAM);
      // Falling back to the granted scope makes this self-healing for a
      // registration created before the scope moved into the URL: the request
      // arrives with no claim, so it gets a tombstone (below) — but *with* a
      // header, so the tombstone can actually install and the stale worker
      // dies. The injected snippet then re-registers at the current URL.
      const echoScope =
        claimed !== undefined && isValidServiceWorkerScope(claimed) ? claimed : grantedScope;

      reply
        .status(200)
        .header("content-type", "text/javascript; charset=utf-8")
        // Always revalidated, so a withdrawn grant converges on the next check.
        .header("cache-control", "no-cache")
        .header("x-content-type-options", "nosniff");

      // No grant / archived / unknown slug / a scope that isn't the granted one
      // ⇒ the tombstone, never a 404: browsers differ on whether a 404 during an
      // update check unregisters or just fails the update, and the latter would
      // make revocation a no-op.
      //
      // The header goes out here too, and that is the whole point of echoing the
      // claimed scope: the max-scope test runs on *every* update check, so a
      // tombstone served without it fails with a SecurityError and never
      // installs — leaving the worker it was meant to kill in place.
      if (grantedScope === undefined || claimed !== grantedScope || !entry?.blobPrefix) {
        if (echoScope !== undefined) reply.header("service-worker-allowed", echoScope);
        await reply.send(buildTombstoneScript());
        return;
      }

      // For a worker, the CSP delivered *with the script* governs the worker's
      // own execution context — served bare, its fetch() would be unbounded by
      // `connect-src 'self'`. This keeps the worker inside the same data-flow
      // containment as the page it serves.
      reply.header("content-security-policy", buildAppCsp(entry.externalOrigins));
      // The one route on the platform that emits this. The script lives at
      // `/_helix/`, so its default max scope is `/_helix/` — controlling the
      // app's prefix requires widening it explicitly. Here the value is the
      // *granted* scope, which the projection already re-validated (never root,
      // never a `_` namespace); the claimed scope only had to match it.
      reply.header("service-worker-allowed", grantedScope);
      await reply.send(
        buildServiceWorkerScript({ scope: grantedScope, cacheVersion: entry.blobPrefix }),
      );
    },
  });

  app.route({
    method: ["GET", "HEAD"],
    url: "/*",
    handler: async (req, reply) => {
      if (req.hostClass.kind === "app") {
        // `/_auth/*` and `/_api/*` are platform namespaces — anything not
        // explicitly routed above 404s rather than reaching the blob store.
        if (isReservedAppPath(req.raw.url ?? "/")) {
          sendNotFound(reply);
          return;
        }
        await serveAsset(req, reply, req.hostClass.slug);
        return;
      }
      sendNotFound(reply);
    },
  });

  // Unmatched methods (POST/PUT/… have no routes above) land here.
  app.setNotFoundHandler((req, reply) => {
    if (req.hostClass.kind === "app" && req.method !== "GET" && req.method !== "HEAD") {
      sendMethodNotAllowed(reply);
      return;
    }
    sendNotFound(reply);
  });

  return app;
}
