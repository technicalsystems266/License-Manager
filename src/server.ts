import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Pool, type QueryResultRow } from "pg";

const databaseUrl = String(process.env.DATABASE_URL || "").replace(/[?&]sslmode=[^&]+/i, "");
const db = databaseUrl ? new Pool({ connectionString: databaseUrl, max: 5, ssl: { rejectUnauthorized: false } }) : null;
const MASTER = process.env.MASTER_API_TOKEN || "";
const BILLING = process.env.BILLING_API_TOKEN || "";
const DEPLOYER = process.env.DEPLOYER_API_TOKEN || "";
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const PRIVATE_KEY = process.env.LICENSE_ENTITLEMENT_PRIVATE_KEY_B64 || process.env.ENTITLEMENT_PRIVATE_KEY_B64 || "";
const COMPONENTS = ["orbitfs_base", "orbitfs_mcp", "orbitfs_apex", "orbitfs_studio"] as const;
const MAX_JSON_BYTES = Math.max(16 * 1024, Number(process.env.MAX_JSON_BODY_BYTES || 1024 * 1024));
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
const adminEmails = new Set((process.env.ADMIN_EMAILS || "").split(",").map((email) => email.trim().toLowerCase()).filter(Boolean));
const configuredOrigins = new Set((process.env.CORS_ORIGINS || "").split(",").map((origin) => origin.trim()).filter(Boolean));

type Role = "master" | "billing" | "deployer";
type JsonObject = Record<string, unknown>;

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const json = (res: ServerResponse, status: number, value: unknown) => {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(value));
};

const text = (res: ServerResponse, status: number, value: string, contentType = "text/plain; charset=utf-8") => {
  res.statusCode = status;
  res.setHeader("content-type", contentType);
  res.setHeader("cache-control", "no-store");
  res.end(value);
};

const bearer = (req: IncomingMessage) => {
  const value = String(req.headers.authorization || "");
  return value.startsWith("Bearer ") ? value.slice(7).trim() : "";
};

const sameSecret = (actual: string, expected: string) => {
  if (!actual || !expected) return false;
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
};

const role = (req: IncomingMessage): Role | null => {
  const token = bearer(req);
  if (sameSecret(token, MASTER)) return "master";
  if (sameSecret(token, BILLING)) return "billing";
  if (sameSecret(token, DEPLOYER)) return "deployer";
  return null;
};

const allowed = (req: IncomingMessage, roles: Role[]) => {
  const current = role(req);
  return current !== null && roles.includes(current);
};

const query = async <T extends QueryResultRow = QueryResultRow>(sql: string, values: unknown[] = []) => {
  if (!db) throw new HttpError(503, "Database is not configured");
  return db.query<T>(sql, values);
};

const readRaw = (req: IncomingMessage, limit: number) => new Promise<Buffer>((resolve, reject) => {
  const declared = Number(req.headers["content-length"] || 0);
  if (declared > limit) {
    reject(new HttpError(413, "Request body is too large"));
    req.resume();
    return;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  req.on("data", (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > limit) {
      req.destroy();
      reject(new HttpError(413, "Request body is too large"));
      return;
    }
    chunks.push(bytes);
  });
  req.on("end", () => resolve(Buffer.concat(chunks)));
  req.on("error", reject);
});

const body = async (req: IncomingMessage, limit = MAX_JSON_BYTES): Promise<JsonObject> => {
  const raw = await readRaw(req, limit);
  if (!raw.length) return {};
  try {
    const parsed = JSON.parse(raw.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("object required");
    return parsed as JsonObject;
  } catch {
    throw new HttpError(400, "Request body must be valid JSON");
  }
};

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const newLicenseKey = () => {
  const value = randomUUID().replaceAll("-", "").toUpperCase();
  return `OFS-${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}`;
};
const privatePem = () => PRIVATE_KEY ? Buffer.from(PRIVATE_KEY, "base64").toString("utf8") : "";
const publicPem = () => {
  const pem = privatePem();
  return pem ? createPublicKey(createPrivateKey(pem)).export({ type: "spki", format: "pem" }).toString() : "";
};
const signingStatus = () => {
  try {
    return Boolean(publicPem());
  } catch {
    return false;
  }
};
const entitlement = (payload: JsonObject) => {
  const pem = privatePem();
  if (!pem) throw new HttpError(503, "Entitlement signing is not configured");
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const claims = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const input = `${header}.${claims}`;
  const signature = sign("RSA-SHA256", Buffer.from(input), createPrivateKey(pem)).toString("base64url");
  return `${input}.${signature}`;
};

const audit = async (type: string, id: string, action: string, actor: string, detail: JsonObject = {}) => {
  await query(
    "insert into audit_log(id,entity_type,entity_id,action,actor_ref,detail) values($1,$2,$3,$4,$5,$6)",
    [randomUUID(), type, id, action, actor, detail],
  );
};

const publicBinding = (binding: JsonObject) => {
  const result = { ...binding };
  delete result.license_key_hash;
  delete result.license_key_last4;
  return result;
};

const authUser = async (req: IncomingMessage): Promise<JsonObject | null> => {
  const token = bearer(req);
  if (!token || !SUPABASE_URL || !(SUPABASE_ANON_KEY || SUPABASE_SERVICE_ROLE_KEY)) return null;
  const authKey = SUPABASE_ANON_KEY || SUPABASE_SERVICE_ROLE_KEY;
  const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: authKey, authorization: ["Bearer", token].join(" ") },
  });
  if (!response.ok) return null;
  const user = await response.json() as JsonObject;
  const appMetadata = (user.app_metadata && typeof user.app_metadata === "object") ? user.app_metadata as JsonObject : {};
  const email = String(user.email || "").toLowerCase();
  return (adminEmails.has(email) || appMetadata.role === "admin") ? user : null;
};

const supabaseAdminRequest = async (path: string, init: RequestInit = {}) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new HttpError(503, "Supabase admin authentication is not configured");
  return fetch(`${SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      authorization: ["Bearer", SUPABASE_SERVICE_ROLE_KEY].join(" "),
      "content-type": "application/json",
      ...(init.headers || {}),
    },
  });
};

const configuredAdminUsers = async () => {
  const response = await supabaseAdminRequest("/auth/v1/admin/users?per_page=1000");
  if (!response.ok) throw new HttpError(502, "Unable to inspect Supabase administrator accounts");
  const data = await response.json() as JsonObject;
  const users = Array.isArray(data.users) ? data.users : [];
  return users.filter((user) => {
    if (!user || typeof user !== "object") return false;
    const item = user as JsonObject;
    const metadata = item.app_metadata && typeof item.app_metadata === "object" ? item.app_metadata as JsonObject : {};
    return metadata.role === "admin" || adminEmails.has(String(item.email || "").toLowerCase());
  });
};

const setupStatus = async () => {
  const missing = [
    !SUPABASE_URL ? "SUPABASE_URL" : "",
    !SUPABASE_ANON_KEY ? "SUPABASE_ANON_KEY" : "",
    !SUPABASE_SERVICE_ROLE_KEY ? "SUPABASE_SERVICE_ROLE_KEY" : "",
  ].filter(Boolean);
  if (missing.length) {
    return { available: false, setupRequired: false, configured: false, missing };
  }
  try {
    const admins = await configuredAdminUsers();
    return { available: true, setupRequired: admins.length === 0, configured: admins.length > 0, missing: [] };
  } catch (error) {
    return {
      available: false,
      setupRequired: false,
      configured: false,
      missing: [],
      error: error instanceof HttpError ? error.message : "Supabase admin authentication rejected the configured service role key",
    };
  }
};

const createInitialAdmin = async (req: IncomingMessage, res: ServerResponse) => {
  const status = await setupStatus();
  if (!status.available) return json(res, 503, { error: "Supabase admin authentication is not configured" });
  if (!status.setupRequired) return json(res, 409, { error: "Administrator setup has already been completed" });
  const input = await body(req);
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, 400, { error: "A valid email is required" });
  if (password.length < 12) return json(res, 400, { error: "Password must be at least 12 characters" });
  const response = await supabaseAdminRequest("/auth/v1/admin/users", {
    method: "POST",
    body: JSON.stringify({ email, password, email_confirm: true, app_metadata: { role: "admin" } }),
  });
  const data = await response.json().catch(() => ({})) as JsonObject;
  if (!response.ok) {
    const message = String(data.msg || data.message || data.error_description || "Administrator account creation failed");
    return json(res, response.status === 422 ? 409 : 502, { error: message });
  }
  return json(res, 201, { ok: true, user: { id: data.id, email: data.email || email } });
};

const requireAdmin = async (req: IncomingMessage) => {
  const user = await authUser(req);
  if (!user) throw new HttpError(401, "Administrator authentication is required");
  return user;
};

const actorFrom = (req: IncomingMessage, fallback = "master") => String(req.headers["x-actor-ref"] || role(req) || fallback).slice(0, 200);

async function issue(req: IncomingMessage, res: ServerResponse, authenticated = false) {
  if (!authenticated && !allowed(req, ["billing", "master"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const orderRef = String(input.orderRef || req.headers["x-orbitfs-order-ref"] || "").trim();
  if (!orderRef || orderRef.length > 200) return json(res, 400, { error: "orderRef is required" });
  if (!db) return json(res, 503, { error: "Database is not configured" });

  const client = await db.connect();
  let created = false;
  try {
    await client.query("begin");
    const existing = (await client.query(
      "select * from license_bindings where order_ref=$1 and archived_at is null for update",
      [orderRef],
    )).rows[0] as JsonObject | undefined;
    let binding: JsonObject;
    let licenseKey: string | undefined;
    if (existing) {
      binding = existing;
      licenseKey = (await client.query("select license_key from license_key_delivery where binding_id=$1 order by created_at desc limit 1", [existing.id])).rows[0]?.license_key;
    } else {
      const components = input.components && typeof input.components === "object" && !Array.isArray(input.components) ? input.components : {};
      const requestedMaxInstallations = Number(input.maxInstallations ?? 1);
      const maxInstallations = Number.isFinite(requestedMaxInstallations)
        ? Math.max(1, Math.min(100, Math.floor(requestedMaxInstallations)))
        : 1;
      licenseKey = newLicenseKey();
      binding = (await client.query(
        `insert into license_bindings
          (id,customer_ref,order_ref,product_code,status,desired_state,remote_state,expires_at,max_installations,components,metadata,license_key_hash,license_key_last4,notes)
         values($1,$2,$3,$4,'active','active','active',$5,$6,$7,$8,$9,$10,$11)
         on conflict (order_ref) where archived_at is null do update set updated_at=license_bindings.updated_at
         returning *`,
        [
          randomUUID(), String(input.customerRef || ""), orderRef, String(input.productCode || "orbitfs_base"),
          input.expiresAt || null, maxInstallations, components, input.metadata || {}, hash(licenseKey),
          licenseKey.slice(-4), input.notes || null,
        ],
      )).rows[0] as JsonObject;
      if (binding && binding.license_key_hash === hash(licenseKey)) {
        created = true;
        await client.query(
          "insert into license_key_delivery(binding_id,customer_ref,license_key) values($1,$2,$3)",
          [binding.id, String(input.customerRef || ""), licenseKey],
        );
        await client.query(
          `insert into license_fulfillments(order_ref,customer_ref,product_code,state,binding_id,license_id,fulfilled_at,metadata)
           values($1,$2,$3,'fulfilled',$4,$4,now(),$5) on conflict(order_ref) do nothing`,
          [orderRef, String(input.customerRef || ""), String(input.productCode || "orbitfs_base"), binding.id, { components }],
        );
      } else {
        licenseKey = (await client.query("select license_key from license_key_delivery where binding_id=$1 order by created_at desc limit 1", [binding?.id])).rows[0]?.license_key;
      }
    }
    await client.query("commit");
    if (created) await audit("licence", String(binding.id), "issued", String(input.actorRef || role(req)), { orderRef });
    return json(res, created ? 201 : 200, {
      licence: publicBinding(binding),
      ...(licenseKey ? { licenceKey: licenseKey } : {}),
      status: binding.status,
      idempotent: !created,
    });
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

async function validate(req: IncomingMessage, res: ServerResponse) {
  const input = await body(req);
  const licenseKey = String(input.licenseKey || input.license_key || "").trim();
  const installationId = String(input.installationId || input.installation_id || "").trim();
  if (!licenseKey || !installationId || licenseKey.length > 200 || installationId.length > 200) {
    return json(res, 400, { error: "licenseKey and installationId are required" });
  }
  const binding = (await query<JsonObject>(
    "select * from license_bindings where license_key_hash=$1 and archived_at is null limit 1",
    [hash(licenseKey)],
  )).rows[0];
  if (!binding) return json(res, 404, { error: "Licence not found", code: "LICENSE_NOT_FOUND" });

  const expired = binding.expires_at && new Date(String(binding.expires_at)).getTime() <= Date.now();
  const state = expired ? "expired" : String(binding.status);
  const requested = Array.isArray(input.components) ? input.components.map(String).slice(0, COMPONENTS.length) : [...COMPONENTS];
  const result: JsonObject = {};
  const client = db ? await db.connect() : null;
  try {
    if (client) await client.query("begin");
    for (const requestedName of requested) {
      const component = requestedName === "orbitfs_panel" ? "orbitfs_base" : requestedName === "orbitfs_sorter" ? "orbitfs_apex" : requestedName;
      if (!COMPONENTS.includes(component as typeof COMPONENTS[number])) {
        result[requestedName] = { allowed: false, state: "blocked", lockedToThisInstallation: false, reason: "unknown_component" };
        continue;
      }
      const components = binding.components && typeof binding.components === "object" ? binding.components as JsonObject : {};
      const enabled = components[component] === true || (component === "orbitfs_base" && Object.keys(components).length === 0);
      let installation = (await (client ?? db)?.query(
        "select * from license_installations where binding_id=$1 and component_key=$2 and installation_id=$3 limit 1",
        [binding.id, component, installationId],
      ))?.rows[0] as JsonObject | undefined;
      if (state === "active" && enabled && input.activate === true && !installation) {
        // Serialize activation per license so concurrent requests cannot exceed the limit.
        if (client) await client.query("select pg_advisory_xact_lock(hashtext($1))", [String(binding.id)]);
        const count = Number((await (client ?? db)?.query(
          "select count(distinct installation_id)::int as count from license_installations where binding_id=$1 and status='active'",
          [binding.id],
        ))?.rows[0]?.count || 0);
        if (count >= Number(binding.max_installations || 1)) {
          if (client) await client.query("rollback");
          return json(res, 409, { error: "Installation limit reached", code: "INSTALLATION_LIMIT" });
        }
        await (client ?? db)?.query(
          `insert into license_installations
            (id,binding_id,component_key,installation_id,device_name,platform,app_version,status,registered_at,last_seen_at,locked_at,metadata)
           values($1,$2,$3,$4,$5,$6,$7,'active',now(),now(),now(),$8)
           on conflict(binding_id,component_key,installation_id) do update
             set status='active',last_seen_at=now(),locked_at=coalesce(license_installations.locked_at,now()),device_name=excluded.device_name,
                 platform=excluded.platform,app_version=excluded.app_version,metadata=excluded.metadata`,
          [randomUUID(), binding.id, component, installationId, input.deviceName || null, input.platform || null, input.appVersion || null, input.metadata || {}],
        );
        installation = (await (client ?? db)?.query(
          "select * from license_installations where binding_id=$1 and component_key=$2 and installation_id=$3 limit 1",
          [binding.id, component, installationId],
        ))?.rows[0] as JsonObject;
      } else if (installation) {
        await (client ?? db)?.query("update license_installations set last_seen_at=now() where id=$1", [installation.id]);
      }
      const allowedComponent = state === "active" && enabled && !!installation && installation.status === "active";
      result[requestedName] = {
        allowed: allowedComponent,
        state: !enabled ? "blocked" : state !== "active" ? state : allowedComponent ? "locked" : "blocked",
        lockedToThisInstallation: !!installation,
        reason: !enabled ? "not_included" : state !== "active" ? state : allowedComponent ? null : "activation_required",
      };
    }
    if (client) await client.query("commit");
  } catch (error) {
    if (client) await client.query("rollback");
    throw error;
  } finally {
    client?.release();
  }

  const settings = (await query<JsonObject>("select * from master_license_settings where id='primary'"))?.rows[0] || {};
  const iat = Math.floor(Date.now() / 1000);
  const ttl = Number(settings.entitlement_ttl_seconds || 10800);
  const grace = Number(settings.grace_seconds || 604800);
  const valid = state === "active" && Object.values(result).some((value) => (value as JsonObject).allowed === true);
  await query(
    "insert into license_validation_log(binding_id,license_id,installation_id,result,reason) values($1,$2,$3,$4,$5)",
    [binding.id, binding.id, installationId, valid ? "allowed" : "denied", valid ? null : state === "active" ? "activation_required" : state],
  );
  return json(res, 200, {
    valid,
    reason: valid ? null : state === "active" ? "activation_required" : state,
    components: result,
    entitlement: entitlement({
      iss: String(settings.issuer || "orbitfs-license-master"), aud: String(settings.audience || "orbitfs-runtime"),
      iat, exp: iat + ttl, graceUntil: iat + ttl + grace, valid, reason: valid ? null : state,
      licenceId: binding.id, installationId, components: result,
    }),
  });
}

async function control(req: IncomingMessage, res: ServerResponse, id: string, authenticated = false) {
  if (!authenticated && !allowed(req, ["master"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const action = String(input.action || "");
  if (!["activate", "suspend", "terminate", "unblock", "unlock", "set_component", "set_expiry"].includes(action)) {
    return json(res, 400, { error: "Invalid action" });
  }
  const row = (await query<JsonObject>("select * from license_bindings where id=$1 and archived_at is null", [id])).rows[0];
  if (!row) return json(res, 404, { error: "Licence not found" });
  if (action === "unlock") {
    await query("update license_installations set status='inactive',locked_at=null,last_seen_at=now() where binding_id=$1", [id]);
  } else if (action === "set_expiry") {
    await query("update license_bindings set expires_at=$1,updated_at=now() where id=$2", [input.expiresAt || null, id]);
  } else if (action === "set_component") {
    const component = String(input.component || "");
    if (!COMPONENTS.includes(component as typeof COMPONENTS[number])) return json(res, 400, { error: "Invalid component" });
    await query(
      "update license_bindings set components=jsonb_set(coalesce(components,'{}'::jsonb),$1,to_jsonb($2::boolean),true),updated_at=now() where id=$3",
      [[component], input.enabled === true, id],
    );
  } else {
    const status = action === "suspend" ? "suspended" : action === "terminate" ? "terminated" : "active";
    await query("update license_bindings set status=$1,desired_state=$1,remote_state=$1,updated_at=now() where id=$2", [status, id]);
  }
  await audit("licence", id, action, String(input.actorRef || actorFrom(req)), { reason: input.reason || null });
  return json(res, 200, { ok: true, licenceId: id, action });
}

async function releases(req: IncomingMessage, res: ServerResponse, authenticated = false) {
  if (req.method === "GET") {
    if (!authenticated && !allowed(req, ["master", "billing", "deployer"])) return json(res, 401, { error: "Unauthorized" });
    const rows = (await query<JsonObject>("select * from releases order by updated_at desc limit 500")).rows;
    return json(res, 200, { releases: rows });
  }
  if (!authenticated && !allowed(req, ["master"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const version = String(input.version || "").trim();
  const component = String(input.component || "orbitfs_base");
  const channel = String(input.channel || "stable");
  if (!version || !COMPONENTS.includes(component as typeof COMPONENTS[number])) return json(res, 400, { error: "version and valid component are required" });
  const existing = (await query<JsonObject>("select * from releases where component=$1 and channel=$2 and version=$3 limit 1", [component, channel, version])).rows[0];
  if (existing) return json(res, 200, { release: existing, idempotent: true });
  const release = (await query<JsonObject>(
    `insert into releases
      (id,component,version,channel,status,title,description,changelog,customer_notes,internal_notes,severity,required,rollout,minimum_version,rollback_version,schema_version,checkpoint_required,components,manifest,permissions,compatibility,source_commit)
     values($1,$2,$3,$4,'draft',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) returning *`,
    [
      randomUUID(), component, version, channel, String(input.title || `OrbitFS ${version}`), String(input.description || ""),
      String(input.changelog || ""), String(input.customerNotes || ""), String(input.internalNotes || ""), String(input.severity || "normal"),
      input.required === true, String(input.rollout || "public"), input.minimumVersion || null, input.rollbackVersion || null,
      String(input.schemaVersion || "1"), input.checkpointRequired === true, input.components || [], input.manifest || {},
      input.permissions || {}, input.compatibility || {}, input.sourceCommit || null,
    ],
  )).rows[0];
  await audit("release", String(release.id), "draft_created", String(input.actorRef || actorFrom(req)), { component, version });
  return json(res, 201, { release });
}

async function releaseAction(req: IncomingMessage, res: ServerResponse, id: string, action: string, authenticated = false) {
  if (!authenticated && !allowed(req, ["master"])) return json(res, 401, { error: "Unauthorized" });
  const row = (await query<JsonObject>("select * from releases where id=$1", [id])).rows[0];
  if (!row) return json(res, 404, { error: "Release not found" });
  if (action === "publish") {
    if (!row.artifact_path) return json(res, 409, { error: "Release artifact must be uploaded before publishing" });
    if (row.status !== "validated") return json(res, 409, { error: "Release must be validated before publishing", status: row.status });
    await query("update releases set status='published',published_at=now(),published_by=$1,updated_at=now() where id=$2", [actorFrom(req), id]);
  } else if (action === "pause" || action === "paused" || action === "withdraw" || action === "withdrawn") {
    const status = action.startsWith("withdraw") ? "withdrawn" : "paused";
    await query("update releases set status=$1,updated_at=now() where id=$2", [status, id]);
  } else if (action === "validate") {
    if (!row.artifact_path || !row.artifact_sha256) return json(res, 422, { valid: false, errors: ["artifact_required"] });
    await query("update releases set status='validated',updated_at=now() where id=$1", [id]);
  } else return json(res, 400, { error: "Invalid release action" });
  await audit("release", id, action, actorFrom(req));
  return json(res, 200, { release: (await query<JsonObject>("select * from releases where id=$1", [id])).rows[0], deploysAutomatically: false });
}

async function artifact(req: IncomingMessage, res: ServerResponse, id: string) {
  if (!allowed(req, ["master"])) return json(res, 401, { error: "Unauthorized" });
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(res, 503, { error: "Supabase storage is not configured" });
  const row = (await query<JsonObject>("select * from releases where id=$1", [id])).rows[0];
  if (!row) return json(res, 404, { error: "Release not found" });
  const bytes = await readRaw(req, MAX_ARTIFACT_BYTES);
  if (!bytes.length) return json(res, 400, { error: "Artifact is empty" });
  const digest = createHash("sha256").update(bytes).digest("hex");
  const expected = String(req.headers["x-artifact-sha256"] || "").toLowerCase();
  if (expected && expected !== digest) return json(res, 400, { error: "Artifact SHA-256 mismatch", expected, actual: digest });
  const path = `releases/${row.component}/${row.channel}/${row.version}/artifact.bin`;
  const storageKey = SUPABASE_SERVICE_ROLE_KEY;
  const upload = await fetch(`${SUPABASE_URL}/storage/v1/object/orbitfs-license-master-releases/${path}`, {
    method: "POST",
    headers: { authorization: ["Bearer", storageKey].join(" "), apikey: storageKey, "content-type": String(req.headers["content-type"] || "application/octet-stream"), "x-upsert": "true" },
    body: new Uint8Array(bytes),
  });
  if (!upload.ok) return json(res, 502, { error: "Artifact storage failed" });
  const fresh = (await query<JsonObject>(
    "update releases set artifact_path=$1,artifact_sha256=$2,artifact_size=$3,artifact_content_type=$4,updated_at=now() where id=$5 returning *",
    [path, digest, bytes.length, req.headers["content-type"] || "application/octet-stream", id],
  )).rows[0];
  await audit("release", id, "artifact_uploaded", actorFrom(req), { sha256: digest, size: bytes.length });
  return json(res, 200, { release: fresh });
}

async function signedDownload(path: string, expiresIn = 300) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new HttpError(503, "Supabase storage is not configured");
  const storageKey = SUPABASE_SERVICE_ROLE_KEY;
  const response = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/orbitfs-license-master-releases/${path}`, {
    method: "POST",
    headers: { authorization: ["Bearer", storageKey].join(" "), apikey: storageKey, "content-type": "application/json" },
    body: JSON.stringify({ expiresIn }),
  });
  if (!response.ok) throw new HttpError(502, "Release download URL creation failed");
  const result = await response.json() as JsonObject;
  const signed = String(result.signedURL || result.signedUrl || result.signed_url || "");
  if (!signed) throw new HttpError(502, "Release download URL was not returned");
  return { downloadUrl: signed.startsWith("http") ? signed : `${SUPABASE_URL}/storage/v1${signed}`, expiresIn };
}

async function latest(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url || "/", "http://localhost");
  const component = url.searchParams.get("component") || "orbitfs_base";
  const channel = url.searchParams.get("channel") || "stable";
  const release = (await query<JsonObject>(
    "select * from releases where component=$1 and channel=$2 and status='published' order by published_at desc limit 1",
    [component, channel],
  )).rows[0];
  if (!release) return json(res, 404, { error: "No published release" });
  return json(res, 200, { release: { ...release, ...(await signedDownload(String(release.artifact_path || ""))) } });
}

async function executeDeployment(req: IncomingMessage, res: ServerResponse) {
  if (!allowed(req, ["billing", "deployer", "master"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const installationId = String(input.installationId || (input.installation && (input.installation as JsonObject).id) || "").trim();
  const releaseId = String(input.releaseId || "").trim();
  const vercelToken = String(input.vercelAccessToken || "").trim();
  if (!installationId || !releaseId || !vercelToken) return json(res, 400, { error: "installationId, releaseId and vercelAccessToken are required" });
  const release = (await query<JsonObject>("select * from releases where id=$1 and status='published'", [releaseId])).rows[0];
  if (!release) return json(res, 404, { error: "Published release not found" });
  if (!release.artifact_path) return json(res, 409, { error: "Release artifact is missing" });
  const job = (await query<JsonObject>(
    `insert into deployment_jobs(id,installation_id,user_ref,binding_id,release_id,action,status,requested_by,progress,message,started_at)
     values($1,$2,$3,$4,$5,$6,'running',$7,5,'Deployment started',now()) returning *`,
    [randomUUID(), installationId, String(input.userRef || ""), input.bindingId || null, releaseId, String(input.action || "deploy"), actorFrom(req)],
  )).rows[0];
  try {
    const signed = await signedDownload(String(release.artifact_path), 600);
    const artifactResponse = await fetch(signed.downloadUrl);
    if (!artifactResponse.ok) throw new Error("Release artifact download failed");
    const manifest = JSON.parse(gunzipSync(Buffer.from(await artifactResponse.arrayBuffer())).toString("utf8")) as JsonObject;
    const teamId = String(input.vercelTeamId || "").trim();
    const projectId = String(input.vercelProjectId || "").trim();
    const projectName = String(input.vercelProjectName || `orbitfs-${installationId.slice(-8)}`).trim();
    const withTeam = (path: string) => {
      const url = new URL(path, "https://api.vercel.com");
      if (teamId) url.searchParams.set("teamId", teamId);
      return url.pathname + url.search;
    };
    const vapi = async (path: string, init: RequestInit = {}) => {
      const response = await fetch(`https://api.vercel.com${withTeam(path)}`, {
        ...init,
        headers: { authorization: ["Bearer", vercelToken].join(" "), "content-type": "application/json", ...(init.headers || {}) },
      });
      if (!response.ok) throw new Error(`Vercel API ${response.status}`);
      return response.status === 204 ? null : response.json();
    };
    let project: { id: string; name: string } | null = projectId ? { id: projectId, name: projectName } : null;
    if (!project) project = await vapi("/v11/projects", { method: "POST", body: JSON.stringify({ name: projectName, framework: "sveltekit" }) });
    await query("update deployment_jobs set progress=25,message='Configuring Vercel project',updated_at=now() where id=$1", [job.id]);
    const env = input.env && typeof input.env === "object" && !Array.isArray(input.env) ? input.env as JsonObject : {};
    for (const [key, value] of Object.entries(env)) {
      await vapi(`/v10/projects/${encodeURIComponent(project.id)}/env?upsert=true`, {
        method: "POST",
        body: JSON.stringify({ key, value: String(value), type: "encrypted", target: ["production", "preview", "development"] }),
      });
    }
    await query("update deployment_jobs set progress=45,message='Uploading release files',updated_at=now() where id=$1", [job.id]);
    const files = Array.isArray(manifest.files) ? manifest.files : [];
    const uploaded: JsonObject[] = [];
    for (const file of files) {
      const item = (file && typeof file === "object") ? file as JsonObject : {};
      const bytes = item.encoding === "base64" ? Buffer.from(String(item.data || ""), "base64") : Buffer.from(String(item.data || ""), "utf8");
      const digest = createHash("sha1").update(bytes).digest("hex");
      const response = await fetch(`https://api.vercel.com${withTeam("/v2/files")}`, {
        method: "POST",
        headers: { authorization: ["Bearer", vercelToken].join(" "), "content-type": "application/octet-stream", "content-length": String(bytes.length), "x-vercel-digest": digest },
        body: new Uint8Array(bytes),
      });
      if (!response.ok && response.status !== 409) throw new Error(`Vercel file upload failed for ${String(item.file || "file")}`);
      uploaded.push({ file: item.file, sha: digest, size: bytes.length });
    }
    await query("update deployment_jobs set progress=75,message='Creating Vercel deployment',updated_at=now() where id=$1", [job.id]);
    const deployment = await vapi("/v13/deployments", {
      method: "POST",
      body: JSON.stringify({
        name: project.name, project: project.id, target: "production", files: uploaded,
        projectSettings: manifest.projectSettings || { framework: "sveltekit", buildCommand: "npm run build", installCommand: "npm ci" },
      }),
    }) as JsonObject;
    const result = {
      jobId: job.id, projectId: project.id, projectName: project.name,
      deploymentId: deployment?.id || deployment?.uid || null,
      deploymentUrl: deployment?.url ? `https://${deployment.url}` : null, version: release.version, releaseId,
    };
    await query("update deployment_jobs set status='completed',progress=100,message='Deployment submitted',result=$1,completed_at=now(),updated_at=now() where id=$2", [result, job.id]);
    await audit("deployment", String(job.id), "completed", actorFrom(req), result);
    return json(res, 200, { ok: true, jobId: job.id, result });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Deployment failed";
    await query("update deployment_jobs set status='failed',progress=100,message='Deployment failed',error=$1,completed_at=now(),updated_at=now() where id=$2", [message, job.id]);
    await audit("deployment", String(job.id), "failed", actorFrom(req), { error: message });
    return json(res, 502, { ok: false, jobId: job.id, error: message });
  }
}

async function syncDeployment(req: IncomingMessage, res: ServerResponse) {
  if (!allowed(req, ["billing", "deployer", "master"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const vercelToken = String(input.vercelAccessToken || "").trim();
  const deploymentId = String(input.vercelDeploymentId || "").trim();
  const teamId = String(input.vercelTeamId || "").trim();
  if (!vercelToken || !deploymentId) return json(res, 400, { error: "vercelAccessToken and vercelDeploymentId are required" });
  const url = new URL(`/v13/deployments/${encodeURIComponent(deploymentId)}`, "https://api.vercel.com");
  if (teamId) url.searchParams.set("teamId", teamId);
  const response = await fetch(url, { headers: { authorization: ["Bearer", vercelToken].join(" ") } });
  if (!response.ok) return json(res, response.status >= 500 ? 502 : response.status, { error: `Vercel API ${response.status}` });
  const deployment = await response.json() as JsonObject;
  const state = String(deployment.readyState || deployment.status || "").toUpperCase();
  return json(res, 200, { state, deploymentId, url: deployment.url ? `https://${deployment.url}` : null, error: deployment.errorMessage || null });
}

async function products(req: IncomingMessage, res: ServerResponse) {
  if (!allowed(req, ["master", "billing", "deployer"])) return json(res, 401, { error: "Unauthorized" });
  return json(res, 200, { products: COMPONENTS.map((code) => ({ code, type: "component", active: true })) });
}

async function installations(req: IncomingMessage, res: ServerResponse, id?: string) {
  if (!allowed(req, ["master", "billing", "deployer"])) return json(res, 401, { error: "Unauthorized" });
  if (req.method === "GET") {
    if (id) {
      const row = (await query<JsonObject>("select * from orbitfs_installations where id=$1", [id])).rows[0];
      return row ? json(res, 200, { installation: row }) : json(res, 404, { error: "Installation not found" });
    }
    return json(res, 200, { installations: (await query<JsonObject>("select * from orbitfs_installations order by updated_at desc limit 500")).rows });
  }
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });
  const input = await body(req);
  const installationId = String(input.installationId || input.id || "").trim();
  if (!installationId || installationId.length > 200) return json(res, 400, { error: "installationId is required" });
  const row = (await query<JsonObject>(`insert into orbitfs_installations
    (id,user_ref,binding_id,hostname,platform,version,vercel_team_id,vercel_project_id,vercel_project_name,metadata,updated_at)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
    on conflict(id) do update set user_ref=excluded.user_ref,binding_id=excluded.binding_id,hostname=excluded.hostname,
    platform=excluded.platform,version=excluded.version,vercel_team_id=excluded.vercel_team_id,
    vercel_project_id=excluded.vercel_project_id,vercel_project_name=excluded.vercel_project_name,
    metadata=excluded.metadata,updated_at=now() returning *`,
    [installationId,input.userRef||null,input.bindingId||null,input.hostname||null,input.platform||null,input.version||null,
     input.vercelTeamId||null,input.vercelProjectId||null,input.vercelProjectName||null,input.metadata||{}])).rows[0];
  await audit("installation", installationId, "registered", actorFrom(req), { bindingId: input.bindingId || null });
  return json(res, 200, { installation: row });
}

async function settings(req: IncomingMessage, res: ServerResponse) {
  if (!allowed(req, ["master"])) return json(res, 401, { error: "Unauthorized" });
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });
  const row = (await query<JsonObject>("select * from master_license_settings where id='primary'")).rows[0] || {};
  return json(res, 200, { settings: row });
}

async function deployments(req: IncomingMessage, res: ServerResponse, id?: string) {
  if (!allowed(req, ["master", "billing", "deployer"])) return json(res, 401, { error: "Unauthorized" });
  if (req.method === "GET" && id) {
    const job = (await query<JsonObject>("select * from deployment_jobs where id=$1", [id])).rows[0];
    return job ? json(res, 200, { job }) : json(res, 404, { error: "Job not found" });
  }
  if (req.method === "GET") return json(res, 200, { jobs: (await query<JsonObject>("select * from deployment_jobs order by created_at desc limit 200")).rows });
  if (!allowed(req, ["master", "billing"])) return json(res, 401, { error: "Unauthorized" });
  const input = await body(req);
  const installationId = String(input.installationId || "");
  const releaseId = String(input.releaseId || "");
  if (!installationId || !releaseId) return json(res, 400, { error: "installationId and releaseId are required" });
  const installation = (await query<JsonObject>("select * from orbitfs_installations where id=$1", [installationId])).rows[0];
  const release = (await query<JsonObject>("select * from releases where id=$1", [releaseId])).rows[0];
  if (!installation) return json(res, 404, { error: "Installation not found" });
  if (!release) return json(res, 404, { error: "Release not found" });
  if (release.status !== "published") return json(res, 409, { error: "Release is not deployable" });
  const job = (await query<JsonObject>(
    `insert into deployment_jobs(id,installation_id,user_ref,binding_id,release_id,action,status,requested_by,progress,message)
     values($1,$2,$3,$4,$5,'deploy','queued',$6,0,'Deployment queued') returning *`,
    [randomUUID(), installationId, installation.user_ref, installation.binding_id, releaseId, actorFrom(req)],
  )).rows[0];
  await audit("deployment", String(job.id), "queued", actorFrom(req), { releaseId, installationId });
  return json(res, 202, { job });
}

async function adminControl(req: IncomingMessage, res: ServerResponse, id: string) {
  await requireAdmin(req);
  return control(req, res, id, true);
}

async function adminIssue(req: IncomingMessage, res: ServerResponse) {
  await requireAdmin(req);
  return issue(req, res, true);
}

const adminPage = () => {
  const html = readFileSync(new URL("../web/admin.html", import.meta.url), "utf8");
  return html.replace("__SUPABASE_URL__", JSON.stringify(SUPABASE_URL)).replace("__SUPABASE_ANON_KEY__", JSON.stringify(SUPABASE_ANON_KEY));
};

export async function handler(req: IncomingMessage, res: ServerResponse) {
  const requestId = String(req.headers["x-request-id"] || randomUUID()).slice(0, 128);
  res.setHeader("x-request-id", requestId);
  const origin = String(req.headers.origin || "");
  const protocol = String(req.headers["x-forwarded-proto"] || (process.env.NODE_ENV === "production" ? "https" : "http")).split(",")[0].trim();
  const sameOrigin = !!origin && !!req.headers.host && origin === `${protocol}://${req.headers.host}`;
  const originAllowed = !origin || sameOrigin || configuredOrigins.has(origin);
  if (originAllowed) {
    res.setHeader("access-control-allow-origin", origin || "*");
    if (origin) res.setHeader("vary", "Origin");
    res.setHeader("access-control-allow-headers", "content-type,authorization,x-orbitfs-order-ref,x-artifact-sha256,x-actor-ref");
    res.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  }

  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  if (req.method === "OPTIONS") return originAllowed ? ((res.statusCode = 204), res.end()) : json(res, 403, { error: "Origin is not allowed" });
  if (!originAllowed) return json(res, 403, { error: "Origin is not allowed" });

  try {
    const url = new URL(req.url || "/", "http://localhost");
    const path = url.pathname;
    if (path === "/") {
      return text(res, 200, adminPage(), "text/html; charset=utf-8");
    }
    if (path === "/favicon.ico") {
      res.statusCode = 204;
      return res.end();
    }
    if (path === "/admin" || path === "/admin/" || path === "/api/admin-ui") return text(res, 200, adminPage(), "text/html; charset=utf-8");
    if (path === "/health" || path === "/api/health") {
      let database = false;
      if (db) {
        try { database = (await query("select 1")).rowCount === 1; } catch { database = false; }
      }
      return json(res, 200, {
        ok: true, service: "OrbitFS License Master", version: "2.0.0", database, signingConfigured: !!privatePem(),
        apiCredentials: { master: !!MASTER, billing: !!BILLING, deployer: !!DEPLOYER },
        adminAuthConfigured: !!SUPABASE_URL && !!SUPABASE_ANON_KEY && !!SUPABASE_SERVICE_ROLE_KEY,
      });
    }
    if (path === "/ready" || path === "/api/ready") {
      let database = false;
      if (db) {
        try {
          database = (await query("select 1")).rowCount === 1;
        } catch {
          database = false;
        }
      }
      const signingConfigured = signingStatus();
      const credentialsConfigured = !!MASTER && !!BILLING && !!DEPLOYER;
      const ready = database && signingConfigured && credentialsConfigured;
      return json(res, ready ? 200 : 503, {
        ok: ready,
        service: "OrbitFS License Master",
        code: !database ? "DATABASE_UNAVAILABLE" : !signingConfigured ? "SIGNING_KEY_INVALID" : !credentialsConfigured ? "API_CREDENTIALS_MISSING" : undefined,
        database, apiCredentials: credentialsConfigured,
        signingConfigured,
      });
    }
    if (path === "/api/license/public-key") {
      try {
        const key = publicPem();
        return key ? text(res, 200, key) : json(res, 503, { error: "Entitlement signing is not configured", code: "SIGNING_KEY_MISSING" });
      } catch {
        return json(res, 503, { error: "Entitlement signing key is invalid", code: "SIGNING_KEY_INVALID" });
      }
    }
    if (path === "/api/license/revision") return json(res, 200, { service: "OrbitFS License Master", version: "2.0.0", authority: "master", components: COMPONENTS });
    if (path === "/api/products" && req.method === "GET") return products(req, res);
    if (path === "/api/settings" && req.method === "GET") return settings(req, res);
    const installationMatch = path.match(/^\/api\/v1\/installations(?:\/([^/]+))?$/);
    if (installationMatch) return installations(req, res, installationMatch[1] ? decodeURIComponent(installationMatch[1]) : undefined);
    if (path === "/api/license/validate" && req.method === "POST") return validate(req, res);
    if (path === "/api/license/issue" && req.method === "POST") return issue(req, res);
    if (path === "/api/admin/licenses/issue" && req.method === "POST") return adminIssue(req, res);
    if (path === "/api/licenses" && req.method === "GET") {
      if (!allowed(req, ["master", "billing"])) return json(res, 401, { error: "Unauthorized" });
      return json(res, 200, { licenses: (await query<JsonObject>("select * from license_bindings where archived_at is null order by created_at desc limit 500")).rows.map(publicBinding) });
    }
    if (path === "/api/admin/me" && req.method === "GET") {
      const user = await requireAdmin(req);
      return json(res, 200, { user: { id: user.id, email: user.email } });
    }
    if (path === "/api/setup/status" && req.method === "GET") return json(res, 200, await setupStatus());
    if (path === "/api/setup/admin" && req.method === "POST") return createInitialAdmin(req, res);
    if (path === "/api/admin/licenses" && req.method === "GET") {
      await requireAdmin(req);
      return json(res, 200, { licenses: (await query<JsonObject>("select * from license_bindings where archived_at is null order by created_at desc limit 500")).rows.map(publicBinding) });
    }
    if (path === "/api/admin/releases" && req.method === "GET") {
      await requireAdmin(req);
      return releases(req, res, true);
    }
    const adminControlMatch = path.match(/^\/api\/admin\/licenses\/([^/]+)\/control$/);
    if (adminControlMatch && req.method === "POST") return adminControl(req, res, decodeURIComponent(adminControlMatch[1]));
    const licenseControlMatch = path.match(/^\/api\/v1\/license\/([^/]+)\/control$/);
    if (licenseControlMatch && req.method === "POST") return control(req, res, decodeURIComponent(licenseControlMatch[1]));
    if (path === "/api/releases" && (req.method === "GET" || req.method === "POST")) return releases(req, res);
    const releaseMatch = path.match(/^\/api\/v1\/releases\/([^/]+)\/(artifact|validate|publish|pause|paused|withdraw|withdrawn|control)$/);
    if (releaseMatch && req.method === "POST") {
      const action = releaseMatch[2] === "artifact" ? null : releaseMatch[2] === "control" ? String((await body(req)).action || "") : releaseMatch[2];
      if (releaseMatch[2] === "artifact") return artifact(req, res, decodeURIComponent(releaseMatch[1]));
      return releaseAction(req, res, decodeURIComponent(releaseMatch[1]), action || "");
    }
    if (path === "/api/releases/latest" && req.method === "GET") return latest(req, res);
    if (path === "/api/deployments/execute" && req.method === "POST") return executeDeployment(req, res);
    if (path === "/api/deployments/sync" && req.method === "POST") return syncDeployment(req, res);
    const deploymentMatch = path.match(/^\/api\/v1\/deployments(?:\/([^/]+))?$/);
    if (deploymentMatch) return deployments(req, res, deploymentMatch[1] ? decodeURIComponent(deploymentMatch[1]) : undefined);
    return json(res, 404, { error: "Not found" });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    if (!(error instanceof HttpError)) {
      console.error(JSON.stringify({
        requestId,
        method: req.method,
        url: req.url,
        error: error instanceof Error ? error.stack || error.message : String(error),
      }));
    }
    return json(res, status, {
      error: status >= 500 ? "Master service error" : error instanceof Error ? error.message : "Request failed",
      requestId,
    });
  }
}

// Vercel may discover imported modules as function entries; expose the same
// callable as a default export so its runtime loader accepts this module.
export default handler;

// Vercel loads this module inside a serverless function; never start the local
// development listener there, even if NODE_ENV is missing from the deployment.
