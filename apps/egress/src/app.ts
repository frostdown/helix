import Fastify, { type FastifyInstance } from "fastify";
import { HealthStatusSchema, OUTCOME_HEADER } from "@azx-pbc/shared";
import { loggerOption } from "@azx-pbc/shared/logging";
import type { EgressConfig } from "./config.js";
import type { SecretResolver } from "./secrets.js";
import type { InstructionBurnStore } from "./burn.js";
import { makeProxyHandler } from "./proxy.js";

/**
 * azx-egress — the mechanism plane (architecture §3). Internal-only: it answers
 * the edge's `/proxy` calls, never app users. It is the one component that holds
 * plaintext secrets and a route to the public internet; everything else about it
 * is deliberately tiny.
 */
export const SERVICE_NAME = "azx-egress";

export interface EgressDeps {
  config: EgressConfig;
  /** null ⇒ no secret store; keyless proxying works, secret-backed calls 502. */
  resolver: SecretResolver | null;
  /** HKDF-derived instruction-verify key (shared derivation with the edge). */
  instructionKey: Buffer;
  /** One-time `jti` burn (issue #3). null ⇒ replay protection off (tests only). */
  burnStore: InstructionBurnStore | null;
}

export function buildApp(deps: EgressDeps): FastifyInstance {
  // The same redacting serializer the edge and portal use (issue #20). Nothing
  // here is query-borne today — `POST /proxy` carries the attested instruction
  // in a header and the target in another — so this is for the next route, not
  // a live leak.
  const app = Fastify({ logger: loggerOption() });

  // The proxy re-streams arbitrary request bodies; never buffer/parse them.
  // `removeAllContentTypeParsers` is essential: Fastify's BUILT-IN
  // `application/json`/`text/plain` parsers would otherwise consume `req.raw`
  // before the handler forwards it (the catch-all `*` only covers types without
  // a parser). The LLM call is always `application/json`, so without this the
  // body reaches the upstream empty. After removing them, the passthrough leaves
  // `req.raw` readable for undici for every content type.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", (_req, payload, done) => done(null, payload));

  // Fastify's default error handler puts `error.message` in the response body,
  // and the edge forwards an egress body to the untrusted app verbatim
  // (`apps/edge/src/gateway/fetch.ts`). In the one process that holds plaintext
  // secrets that is a leak channel, not just noise: V8 embeds a ~10-character
  // prefix of its input in a `JSON.parse` message, so a throw anywhere near
  // credential material would hand the app a fragment of a live key. Answer with
  // a fixed opaque body and keep the detail on the log, where it belongs. Every
  // deliberate refusal already returns through the proxy's own `fail()`, so
  // reaching here at all means an unhandled throw.
  app.setErrorHandler((err, req, reply) => {
    req.log.error({ err }, "unhandled error in egress");
    reply.header(OUTCOME_HEADER, "error");
    reply.code(500).send({ code: "upstream_error", message: "egress request failed" });
  });

  app.route({
    method: ["GET", "HEAD"],
    url: "/health",
    handler: async () =>
      HealthStatusSchema.parse({
        status: "ok",
        service: SERVICE_NAME,
        uptime: process.uptime(),
      }),
  });

  const proxy = makeProxyHandler({
    instructionKey: deps.instructionKey,
    resolver: deps.resolver,
    burnStore: deps.burnStore,
    limits: deps.config.limits,
    allowPrivate: deps.config.allowPrivate,
    allowInsecureConnection: deps.config.allowInsecureConnection,
  });
  // The proxy holds one shared, long-lived dispatcher (connection pooling +
  // per-connection SSRF pin); drain its pooled sockets on teardown so tests and
  // graceful shutdown don't leak keep-alive handles.
  app.addHook("onClose", () => proxy.dispatcher.close());

  app.route({
    method: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    url: "/proxy",
    handler: proxy.handler,
  });

  return app;
}
