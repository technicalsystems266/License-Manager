import { readFileSync, writeFileSync } from "node:fs";

const helper = [
  'const normalizeDatabaseUrl = (value) => {',
  '  const raw = String(value || "").replace(/[?&]sslmode=[^&]+/i, "");',
  '  if (!raw) return raw;',
  '  try {',
  '    const url = new URL(raw);',
  '    const match = url.hostname.match(/^db\\.([a-z0-9]+)\\.supabase\\.co$/i);',
  '    if (!match) return raw;',
  '    const projectRef = match[1];',
  '    const region = String(process.env.SUPABASE_DB_REGION || "us-west-2").trim();',
  '    const poolerHost = String(process.env.SUPABASE_POOLER_HOST || "aws-0-" + region + ".pooler.supabase.com").trim();',
  '    url.hostname = poolerHost;',
  '    url.port = "6543";',
  '    if (url.username === "postgres") url.username = "postgres." + projectRef;',
  '    return url.toString();',
  '  } catch {',
  '    return raw;',
  '  }',
  '};',
  '',
].join("\\n");

const patch = (path, marker, replacement) => {
  let source = readFileSync(path, "utf8");
  if (!source.includes("const normalizeDatabaseUrl = (value) =>")) {
    if (!source.includes(marker)) throw new Error(`${path}: database marker not found`);
    source = source.replace(marker, helper + replacement, 1);
  } else if (source.includes(marker)) {
    source = source.replace(marker, replacement, 1);
  }
  writeFileSync(path, source);
};

patch(
  "api/admin-settings.ts",
  'const DATABASE_URL = String(process.env.DATABASE_URL || "").replace(/[?&]sslmode=[^&]+/i, "");',
  'const DATABASE_URL = normalizeDatabaseUrl(process.env.DATABASE_URL || "");',
);

patch(
  "api/release-control.ts",
  'const dbUrl=String(process.env.DATABASE_URL||"").replace(/[?&]sslmode=[^&]+/i,"");',
  'const dbUrl=normalizeDatabaseUrl(process.env.DATABASE_URL||"");',
);

patch(
  "api/release-capture.ts",
  'const dbUrl=String(process.env.DATABASE_URL||"").replace(/[?&]sslmode=[^&]+/i,"");',
  'const dbUrl=normalizeDatabaseUrl(process.env.DATABASE_URL||"");',
);

console.log("Supabase Postgres connections normalized for Vercel serverless transport");
