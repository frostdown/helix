import Fastify, { type FastifyInstance } from "fastify";
import multipart from "@fastify/multipart";
import { HealthStatusSchema } from "@azx-pbc/shared";
import { loggerOption } from "@azx-pbc/shared/logging";
import type { PrismaClient } from "./db/client.js";
import type { BlobStore } from "./blob/store.js";
import type { SecretStore } from "@azx-pbc/secret-store";
import { prismaPlugin } from "./plugins/prisma.js";
import { blobPlugin } from "./plugins/blob.js";
import { secretStorePlugin } from "./plugins/secretStore.js";
import { errorsPlugin } from "./plugins/errors.js";
import { authPlugin, type AuthPluginOptions } from "./plugins/auth.js";
import { assertBundleLimits, resolveMaxTotalBytes } from "./deploy/limits.js";
import { appRoutes } from "./routes/apps.js";
import { secretRoutes } from "./routes/secrets.js";
import { devTokenRoutes } from "./routes/devTokens.js";
import { approvalRoutes } from "./routes/approvals.js";
import { cspRoutes } from "./routes/csp.js";
import { versionRoutes } from "./routes/versions.js";
import { usageRoutes } from "./routes/usage.js";
import { dataRoutes } from "./routes/data.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { authRoutes } from "./routes/auth.js";
import { configRoutes } from "./routes/config.js";
import { resolveSpaDist, spaRoutes } from "./routes/spa.js";
import { assertDeploymentConfig } from "./deployment.js";

/**
 * azx-portal — the control plane (architecture §3, §7). Privileged: registry
 * writes, deploy endpoint, capability approvals. Not routable from app
 * subdomains. Owns the Postgres schema and migrations (Prisma).
 */
export const SERVICE_NAME = "azx-portal";

export interface BuildAppOptions {
  /** Inject a PrismaClient and BlobStore (tests). Defaults build real ones. */
  prisma?: PrismaClient;
  blobStore?: BlobStore;
  /** Inject the auth verifier chain / public config (tests). */
  auth?: AuthPluginOptions;
  /** Inject the secret-store custody (tests). Defaults build from the env. */
  secretStore?: SecretStore | null;
  /**
   * Built-SPA directory; null forces the stopgap dashboard (tests),
   * undefined auto-detects ($PORTAL_WEB_DIST or apps/portal-web/dist).
   */
  spaDist?: string | null;
}

export function buildApp(opts: BuildAppOptions = {}): FastifyInstance {
  // Fail the boot, not each request: a production portal without APP_PUBLIC_BASE
  // would hand every client — portal UI and `helix` alike — unreachable dev URLs.
  assertDeploymentConfig();
  // Likewise for the deploy size caps: a bad DEPLOY_MAX_*_MB should fail the
  // boot, not the first deploy that happens to hit the validator.
  assertBundleLimits();

  const app = Fastify({
    // The SPA's OIDC redirect URI is `/auth/callback?code=…` on this very
    // origin (routes/spa.ts serves it as a deep link), so the portal logs the
    // same shape of credential the edge does — same stdout, same Log Analytics
    // retention. Redact it (issue #20 — `@azx-pbc/shared/logging`).
    logger: loggerOption(),
  });

  app.register(errorsPlugin);
  app.register(prismaPlugin, { client: opts.prisma });
  app.register(blobPlugin, { store: opts.blobStore });
  app.register(secretStorePlugin, { store: opts.secretStore });
  app.register(authPlugin, opts.auth ?? {});
  // One bundle file per upload; cap the (compressed) upload size. Resolved once
  // at build time — this bounds what `spoolUpload` writes to the replica's temp
  // disk, so it is a capacity decision, not a per-request one.
  app.register(multipart, { limits: { files: 1, fileSize: resolveMaxTotalBytes() } });

  app.get("/health", async () => {
    return HealthStatusSchema.parse({
      status: "ok",
      service: SERVICE_NAME,
      uptime: process.uptime(),
    });
  });

  app.register(appRoutes);
  app.register(secretRoutes);
  app.register(devTokenRoutes);
  app.register(approvalRoutes);
  app.register(cspRoutes);
  app.register(versionRoutes);
  app.register(usageRoutes);
  app.register(dataRoutes);
  app.register(authRoutes);
  app.register(configRoutes);

  // The real dashboard when a built SPA is present; the M2 stopgap otherwise.
  const spaDist = opts.spaDist !== undefined ? opts.spaDist : resolveSpaDist();
  app.decorate("spaDist", spaDist);
  if (spaDist) {
    app.register(spaRoutes);
  } else {
    app.register(dashboardRoutes);
  }

  return app;
}
