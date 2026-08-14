# submit-survey — hardened submission endpoint

Optional upgrade path that adds **CAPTCHA + rate limiting** to survey submission and
lets you lock the table down so the public anon key can do *nothing*.

## Why
Today the browser posts directly to PostgREST with the anon key. RLS + the CHECK
constraints (see `../../../supabase_hardening.sql`) stop reads and malformed rows,
but there's no per-IP throttling — a script can still submit many *valid-looking*
rows. This function closes that gap.

## Prerequisites
1. Run `supabase_hardening.sql` (creates `submission_rate_log` **and** the
   `check_and_log_submission` RPC this function relies on for atomic rate limiting).
2. Cloudflare Turnstile site — get a **site key** (public, goes in the page) and a
   **secret key** (goes in function env). Give the widget a stable `data-action`
   (e.g. `submit_survey`) if you want the function to verify the action too.
3. Supabase CLI linked to project ref `kigvrcsuqrapharysogb`.
4. `supabase/config.toml` present with `verify_jwt = false` for this function
   (see the repo's `config.toml`). This function is public and is called with **no**
   Authorization header — without this, Supabase's gateway 401s the request before
   the code runs.
5. Confirm the **production hostname** first. The ticket asked for
   `foolingmyself.backtothebible.org`; the examples below use a placeholder. Use the
   real name consistently in `ALLOWED_ORIGIN`, the Turnstile widget's allowed
   hostnames, and (if set) `TURNSTILE_EXPECTED_HOSTNAME`.

## Deploy
```bash
supabase secrets set \
  TURNSTILE_SECRET=xxxxxxxx \
  ALLOWED_ORIGIN=https://foolingmyself.backtothebible.org \
  IP_HASH_PEPPER="$(openssl rand -hex 32)" \
  --project-ref kigvrcsuqrapharysogb
# SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically.
#
# Optional:
#   TURNSTILE_EXPECTED_HOSTNAME  (defaults to ALLOWED_ORIGIN's host)
#   TURNSTILE_EXPECTED_ACTION    (must match the widget's data-action, if you set one)
#
# ALLOWED_ORIGIN is REQUIRED — the function fails closed (no "*" fallback) if it's unset.
# IP_HASH_PEPPER is the secret salt for the rate-limit IP HMAC — set it once and keep it.

# Deploy from the repo root so config.toml (verify_jwt = false) is applied.
# Equivalent one-off if you're not deploying from the config: add --no-verify-jwt.
supabase functions deploy submit-survey --project-ref kigvrcsuqrapharysogb
```

Function URL: `https://kigvrcsuqrapharysogb.supabase.co/functions/v1/submit-survey`

## Client changes (the cutover — not yet applied to index.html)
The live page still uses the direct anon path so nothing is broken. When you're
ready to switch:

1. Add the Turnstile widget script + a `<div class="cf-turnstile" data-sitekey="..."
   data-action="submit_survey">` on the reflection screen, and read the token with
   `turnstile.getResponse()`. (The `data-action` is only required if you set
   `TURNSTILE_EXPECTED_ACTION` on the function.)
2. In `saveResults()`, change the `fetch` target from
   `SUPABASE_URL + "/rest/v1/" + TABLE` to the function URL, drop the `apikey`/
   `Authorization` headers, and include `turnstileToken` in the JSON body.
3. After confirming it works end to end, remove the anon INSERT policy + grant:
   ```sql
   drop policy if exists "anon can insert survey responses"
     on public.lying_to_myself_survey_responses;
   revoke insert on public.lying_to_myself_survey_responses from anon;
   ```

Tell Claude "wire the survey to the edge function" and it can apply steps 1–2.

## Tunables (top of index.ts)
- `RATE_LIMIT` / `RATE_WINDOW_SECONDS` — default 5 per 60s per IP.
- `ALLOWED_KEYS` — the only fields forwarded to the DB.
- `MAX_BODY_BYTES` — request body cap (default 24 KB); oversized bodies get 413.
- `*_TIMEOUT_MS` — network timeouts for Turnstile, the rate-limit RPC, and the insert.

## Fail-closed behavior (by design)
- Missing `ALLOWED_ORIGIN` → 500 (won't serve every origin).
- Turnstile timeout/error, or hostname/action mismatch → treated as a failed CAPTCHA (403).
- Rate-limit RPC can't be reached/errors → 503 (won't silently allow the submission).
- Rate limiting is a single atomic **check-and-reserve** in the DB, so simultaneous
  requests can't all slip through the same window.
