// Supabase Edge Function: submit-survey
// -----------------------------------------------------------------------------
// Hardened submission endpoint for the "Lying to Myself" survey.
//
// Order of operations:
//   1. Fail closed if misconfigured (no ALLOWED_ORIGIN) instead of serving "*".
//   2. CORS + POST-only + body-size cap.
//   3. Verify a Cloudflare Turnstile token — success AND hostname (AND action,
//      if configured) — with a network timeout (fail closed on timeout/error).
//   4. Whitelist + validate the payload (DB CHECK constraints remain the
//      authoritative backstop — see supabase_hardening.sql).
//   5. Atomically check + RESERVE a per-IP rate-limit slot via an RPC
//      (fail closed: 503 if the check can't run).
//   6. Insert via the service role key (bypasses RLS).
//
// Required environment variables (set with `supabase secrets set ...`):
//   SUPABASE_URL                - project URL (auto-populated in most setups)
//   SUPABASE_SERVICE_ROLE_KEY   - service role key (NEVER ships to the browser)
//   TURNSTILE_SECRET            - Cloudflare Turnstile secret key
//   ALLOWED_ORIGIN              - REQUIRED. No wildcard fallback. Must be the
//                                 real production origin, e.g.
//                                 https://foolingmyself.backtothebible.org
//   IP_HASH_PEPPER              - secret salt for the rate-limit IP HMAC
// Optional:
//   TURNSTILE_EXPECTED_HOSTNAME - defaults to ALLOWED_ORIGIN's host
//   TURNSTILE_EXPECTED_ACTION   - if set, the widget's data-action must match
//
// IMPORTANT: this function MUST be deployed with verify_jwt = false
// (see supabase/config.toml) — it is called from the page with no
// Authorization header, so the default JWT gate would 401 it before this runs.
//
// Deploy (from the repo root so config.toml is picked up):
//   supabase functions deploy submit-survey --project-ref kigvrcsuqrapharysogb
// -----------------------------------------------------------------------------

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const TURNSTILE_SECRET = Deno.env.get("TURNSTILE_SECRET")!;
// Fail closed: no "*" fallback. If unset, the function refuses to serve.
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "";
const IP_HASH_PEPPER = Deno.env.get("IP_HASH_PEPPER") ?? "";

function hostOf(o: string): string {
  try { return new URL(o).host; } catch { return ""; }
}
const EXPECTED_HOSTNAME =
  Deno.env.get("TURNSTILE_EXPECTED_HOSTNAME") ?? hostOf(ALLOWED_ORIGIN);
const EXPECTED_ACTION = Deno.env.get("TURNSTILE_EXPECTED_ACTION") ?? "";

const TABLE = "lying_to_myself_survey_responses";
const RATE_LIMIT = 5;            // max submissions per IP per window
const RATE_WINDOW_SECONDS = 60;

const MAX_BODY_BYTES = 24_000;   // generous cap for this survey's payload
const TURNSTILE_TIMEOUT_MS = 10_000;
const RPC_TIMEOUT_MS = 8_000;
const INSERT_TIMEOUT_MS = 8_000;

// Only these keys are ever forwarded to the DB (blocks column injection like
// id / created_at, and unknown junk fields).
const ALLOWED_KEYS = new Set<string>([
  ...Array.from({ length: 20 }, (_, i) => `q${i + 1}`),
  "q21_afterlife_belief",
  "q22_bible_days_per_week",
  "q23_discipling_frequency",
  "q24_gender",
  "q25_age_bracket",
  "top3_questions",
  "reflection_lie_text",
  "reflection_avoids",
  "reflection_cost_text",
  "reflection_step_text",
]);

const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// Rate-limit identifier: HMAC(pepper, ip + UTC-date). Not a raw IP, and not a
// plain SHA-256 (which is brute-forceable across the small IPv4 space). Mixing
// in the date bounds correlation to a single day; the log is purged after 1 day.
async function ipTag(ip: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(IP_HASH_PEPPER),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${ip || "unknown"}:${day}`),
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
  const form = new FormData();
  form.append("secret", TURNSTILE_SECRET);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  let data: { success?: boolean; hostname?: string; action?: string };
  try {
    const resp = await fetchWithTimeout(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: form },
      TURNSTILE_TIMEOUT_MS,
    );
    data = await resp.json().catch(() => ({ success: false }));
  } catch {
    return false; // timeout / network error -> fail closed
  }
  if (data.success !== true) return false;
  // Confirm the token was issued for OUR site (and action, if we set one),
  // not solved elsewhere and replayed here.
  if (EXPECTED_HOSTNAME && data.hostname !== EXPECTED_HOSTNAME) return false;
  if (EXPECTED_ACTION && data.action !== EXPECTED_ACTION) return false;
  return true;
}

function restHeaders(extra: Record<string, string> = {}) {
  return {
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    "content-type": "application/json",
    ...extra,
  };
}

// Atomic check-and-reserve via a SECURITY DEFINER RPC (see supabase_hardening.sql).
// Returns: "ok" (slot reserved), "limited" (over limit), "error" (couldn't check).
async function reserveRateSlot(tag: string): Promise<"ok" | "limited" | "error"> {
  try {
    const resp = await fetchWithTimeout(
      `${SUPABASE_URL}/rest/v1/rpc/check_and_log_submission`,
      {
        method: "POST",
        headers: restHeaders(),
        body: JSON.stringify({
          p_ip_hash: tag,
          p_limit: RATE_LIMIT,
          p_window_seconds: RATE_WINDOW_SECONDS,
        }),
      },
      RPC_TIMEOUT_MS,
    );
    if (!resp.ok) return "error";
    const parsed = await resp.json().catch(() => null);
    const overLimit = Array.isArray(parsed) ? parsed[0] : parsed;
    if (typeof overLimit !== "boolean") return "error";
    return overLimit ? "limited" : "ok";
  } catch {
    return "error";
  }
}

// Light validation — DB CHECK constraints are authoritative, but we reject
// obvious junk (wrong types, out-of-range values, oversized elements) up front.
function sanitize(raw: Record<string, unknown>): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!ALLOWED_KEYS.has(k)) continue; // drop unknown keys
    out[k] = v;
  }

  // 20 core answers: all present, integers 0-10.
  for (let i = 1; i <= 20; i++) {
    const v = out[`q${i}`];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 10) return null;
  }

  if ("q22_bible_days_per_week" in out) {
    const v = out["q22_bible_days_per_week"];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 7) return null;
  }

  // Single-choice text answers: short strings (DB pins the exact values).
  for (const f of [
    "q21_afterlife_belief",
    "q23_discipling_frequency",
    "q24_gender",
    "q25_age_bracket",
  ]) {
    const v = out[f];
    if (v != null && (typeof v !== "string" || v.length > 300)) return null;
  }

  // Free-text: strings, capped.
  for (const f of ["reflection_lie_text", "reflection_cost_text", "reflection_step_text"]) {
    const v = out[f];
    if (v != null && (typeof v !== "string" || v.length > 2000)) return null;
  }

  // JSON arrays: correct type, bounded count, bounded element type/size.
  const top3 = out["top3_questions"];
  if (top3 != null) {
    if (!Array.isArray(top3) || top3.length > 20) return null;
    for (const el of top3) {
      if (typeof el !== "number" || !Number.isInteger(el) || el < 1 || el > 25) return null;
    }
  }
  const avoids = out["reflection_avoids"];
  if (avoids != null) {
    if (!Array.isArray(avoids) || avoids.length > 50) return null;
    for (const el of avoids) {
      if (typeof el !== "string" || el.length > 200) return null;
    }
  }

  return out;
}

Deno.serve(async (req) => {
  // Fail closed on misconfiguration rather than allowing every origin.
  if (!ALLOWED_ORIGIN) {
    return new Response(
      JSON.stringify({ error: "server_misconfigured" }),
      { status: 500, headers: { "content-type": "application/json" } },
    );
  }

  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  // Body-size cap (before parse) so a giant payload can't be buffered/parsed.
  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return json(413, { error: "payload_too_large" });

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(raw);
  } catch {
    return json(400, { error: "invalid_json" });
  }

  const token = String(body["turnstileToken"] ?? "");
  if (!token) return json(400, { error: "missing_captcha" });

  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();

  // 1) CAPTCHA (success + hostname/action + timeout)
  if (!(await verifyTurnstile(token, ip))) {
    return json(403, { error: "captcha_failed" });
  }

  // 2) Whitelist + validate (before consuming a rate slot)
  delete body["turnstileToken"];
  const clean = sanitize(body);
  if (!clean) return json(422, { error: "validation_failed" });

  // 3) Atomically reserve a rate-limit slot (fail closed: 503 if it can't run)
  const tag = await ipTag(ip);
  const slot = await reserveRateSlot(tag);
  if (slot === "limited") return json(429, { error: "rate_limited" });
  if (slot === "error") return json(503, { error: "rate_check_unavailable" });

  // 4) Insert response (service role -> bypasses RLS)
  let insertResp: Response;
  try {
    insertResp = await fetchWithTimeout(
      `${SUPABASE_URL}/rest/v1/${TABLE}`,
      {
        method: "POST",
        headers: restHeaders({ Prefer: "return=minimal" }),
        body: JSON.stringify(clean),
      },
      INSERT_TIMEOUT_MS,
    );
  } catch {
    return json(503, { error: "insert_unavailable" });
  }
  if (!insertResp.ok) {
    const detail = await insertResp.text();
    console.error("insert failed", insertResp.status, detail);
    return json(400, { error: "insert_failed" });
  }

  return json(201, { ok: true });
});
