import type { IncomingMessage, ServerResponse } from "node:http";

const SUPABASE_URL = String(process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const MASTER = process.env.MASTER_API_TOKEN || "";
const ADMIN_EMAILS = new Set((process.env.ADMIN_EMAILS || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean));

type Settings = {
  id: string;
  issuer: string;
  audience: string;
  entitlement_ttl_seconds: number;
  grace_seconds: number;
  api_mode: string;
  allow_offline_grace: boolean;
  revision: number;
  updated_at: string;
};

const json = (res: ServerResponse, status: number, value: unknown) => {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(value));
};

const token = (req: IncomingMessage) => String(req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();

async function admin(req: IncomingMessage) {
  const t = token(req);
  if (!t) return false;
  if (MASTER && t === MASTER) return true;
  if (!SUPABASE_URL || !SERVICE) return false;
  const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: SERVICE, authorization: `Bearer ${t}` },
  });
  if (!r.ok) return false;
  const u = await r.json() as { email?: string; app_metadata?: { role?: string } };
  return ADMIN_EMAILS.has(String(u.email || "").toLowerCase()) || u.app_metadata?.role === "admin";
}

function dbHeaders() {
  if (!SUPABASE_URL || !SERVICE) throw new Error("Supabase database is not configured");
  return {
    apikey: SERVICE,
    authorization: `Bearer ${SERVICE}`,
    "content-type": "application/json",
  };
}

async function getSettings(): Promise<Settings> {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/master_license_settings?id=eq.primary&select=id,issuer,audience,entitlement_ttl_seconds,grace_seconds,api_mode,allow_offline_grace,revision,updated_at`, {
    headers: dbHeaders(),
    cache: "no-store",
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Supabase settings query failed (${r.status}): ${typeof body === "object" && body && "message" in body ? String((body as { message?: unknown }).message) : "database request failed"}`);
  const row = Array.isArray(body) ? body[0] : null;
  if (!row) throw new Error("License Master settings row is unavailable");
  return row as Settings;
}

async function updateSettings(input: Record<string, unknown>): Promise<Settings> {
  const current = await getSettings();
  const mode = String(input.api_mode ?? input.mode ?? current.api_mode ?? "online").toLowerCase();
  if (!["online", "offline", "maintenance"].includes(mode)) throw new Error("api_mode must be online, offline, or maintenance");
  const payload = {
    issuer: String(input.issuer ?? current.issuer ?? "orbitfs-license-master"),
    audience: String(input.audience ?? current.audience ?? "orbitfs-runtime"),
    entitlement_ttl_seconds: Math.max(60, Math.floor(Number(input.entitlement_ttl_seconds ?? current.entitlement_ttl_seconds ?? 10800))),
    grace_seconds: Math.max(0, Math.floor(Number(input.grace_seconds ?? current.grace_seconds ?? 604800))),
    api_mode: mode,
    allow_offline_grace: input.allow_offline_grace === undefined ? current.allow_offline_grace !== false : Boolean(input.allow_offline_grace),
    revision: Math.max(1, Math.floor(Number(input.revision ?? Number(current.revision || 0) + 1))),
    updated_at: new Date().toISOString(),
  };
  const r = await fetch(`${SUPABASE_URL}/rest/v1/master_license_settings?id=eq.primary`, {
    method: "PATCH",
    headers: { ...dbHeaders(), Prefer: "return=representation" },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Supabase settings update failed (${r.status}): ${typeof body === "object" && body && "message" in body ? String((body as { message?: unknown }).message) : "database request failed"}`);
  const row = Array.isArray(body) ? body[0] : null;
  if (!row) throw new Error("License Master settings update returned no row");
  return row as Settings;
}

async function readBody(req: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  if (!chunks.length) return {};
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Request body must be an object");
  return value as Record<string, unknown>;
}

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  try {
    if (!(await admin(req))) return json(res, 401, { error: "Administrator authentication is required" });
    if (req.method === "GET") return json(res, 200, { ok: true, settings: await getSettings(), database: true, settings_found: true });
    if (req.method !== "PATCH" && req.method !== "POST") return json(res, 405, { error: "Method not allowed" });
    return json(res, 200, { ok: true, settings: await updateSettings(await readBody(req)), database: true, settings_found: true });
  } catch (e) {
    return json(res, 503, { ok: false, database: false, settings_found: false, error: e instanceof Error ? e.message : "License Master settings operation failed" });
  }
}
