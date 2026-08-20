import { readFileSync } from "node:fs";
import { startTelemetry } from "@azx-pbc/telemetry";
import { SERVICE_NAME, buildApp } from "./app.js";

/**
 * Dev convenience: load `apps/portal/.env.local` (gitignored) into process.env
 * before config. As a developer-local override file (the `.env.local`
 * convention), its values WIN over the inherited environment — so you can
 * repoint the portal at a different IdP (e.g. real Entra) without editing the
 * committed devcontainer env. Absent in prod/CI (it's gitignored), where this
 * is a no-op. Mirrors the edge loader (`apps/edge/src/server.ts`).
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

const port = Number(process.env.PORTAL_PORT ?? process.env.PORT ?? 3001);
const host = process.env.HOST ?? "0.0.0.0";

const app = buildApp();

app.addHook("onClose", async () => {
  await telemetry.shutdown();
});

try {
  await app.listen({ port, host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
