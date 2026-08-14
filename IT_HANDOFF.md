# Lying-to-Myself Survey — Security Hardening Handoff

**Prepared for:** BTTB IT / DBA review
**Supabase project:** "Surveys" — ref `kigvrcsuqrapharysogb`
**Table:** `public.lying_to_myself_survey_responses`
**Repo:** `github.com/BacktotheBible/Lying-to-myself-Survey` (branch `main`)

Attached files referenced below:
- `supabase_setup.sql` — original table + RLS create (already applied)
- `supabase_hardening.sql` — **the main file to run** (validation, grants, retention, rate-limit RPC)
- `supabase/functions/submit-survey/index.ts` + `README.md` — Edge Function (not yet deployed)
- `supabase/config.toml` — sets `verify_jwt = false` for the public `submit-survey` function (required, see Step D)

> **Name change:** the survey and its production hostname were renamed from
> "Lying to Myself" / `lyingtomyself.backtothebible.org` to "Am I Fooling Myself?" /
> `foolingmyself.backtothebible.org` after this doc was first drafted. The page
> title, `CNAME`, and this document have been updated to the new name. **Two
> things outside this repo still need the new hostname applied by whoever has
> access:**
> 1. The Edge Function's `ALLOWED_ORIGIN` secret (currently unknown/possibly still
>    set to the old name — re-run the `supabase secrets set` command in Step D
>    with the new hostname).
> 2. The Cloudflare Turnstile widget's allowed-hostname configuration.
>
> **Confirm the production hostname before deploying.** Use it consistently in
> `ALLOWED_ORIGIN`, the Turnstile widget's allowed hostnames, and the CORS origin,
> or the widget/CORS will fail at go-live.

---

## 1. Current state (already live)

- Survey front-end points at the new Surveys project; old project (`kddfedrklpavwjjdenor`) is no longer written to by the org survey.
- Table created; **RLS enabled**; single policy `anon` = **INSERT only** (no SELECT/UPDATE/DELETE for the public key). Verified: anon POST returns 201; anon GET/UPDATE/DELETE are blocked.
- Privacy notice is live: states answers-only (no name/email/login), reviewed by BTTB team in aggregate, **24-month retention**, and asks users not to put identifying info in free-text.
  - *Once the Edge Function is live:* add one line so the notice is accurate about anti-abuse processing — a short-lived, non-identifying rate-limit record (an HMAC of the IP, kept ≤ 1 day, no raw IP) is used to prevent spam. It should not read as "no technical data at all is processed."

## 2. What is still outstanding

| # | Task | Owner | Status | Blocks which IT finding |
|---|------|-------|--------|--------------------------|
| A | Run `supabase_hardening.sql` | DBA | ✅ done & verified | Column validation + unbounded free-text/jsonb |
| B | Confirm `q21` validation choice (length-cap vs exact-pin) | IT/BTTB | open | (validation completeness) |
| C | Get Cloudflare **Turnstile** keys (site + secret) | IT | ✅ done | Rate-limiting / bot abuse |
| D | Deploy Edge Function `submit-survey` (with `verify_jwt = false` + env secrets) | Dev/DBA | ✅ deployed & smoke-tested | Rate-limiting + permissive-policy |
| E | Wire client to Edge Function, then drop anon INSERT | Dev | client wired (staged); drop-anon pending go-live | Permissive-policy finding (definitive) |
| F | Review OLD project RLS + decide on historical data | DBA | open | (old project still holds prior responses) |
| G | Re-run Supabase linter to confirm findings cleared | IT | open | Verification |
| H | **DNS**: create record `foolingmyself` → `backtothebible.github.io` (CNAME), then verify the domain in GitHub Pages **before** DNS goes live | IT | in progress (name changed from `lyingtomyself`; old record was never created, so this is a clean swap) | Go-live (serves the page at the pinned Turnstile/CORS hostname) |

**Two-layer summary:** Task A closes the two *validation* findings. Tasks C–E close the *permissive insert* and *no rate-limiting* findings. Both layers must be applied before Item 2 is fully resolved.

---

## 3. Walkthrough

### Step A — Run the hardening SQL  *(clears validation findings)*
Supabase Dashboard → Surveys project → **SQL Editor** → paste the full contents of `supabase_hardening.sql` → Run. It is idempotent (safe to re-run). It performs:

1. **Deletes the migration test row** (a single row Claude inserted to verify the insert path).
2. **Defense-in-depth grants** — `REVOKE SELECT, UPDATE, DELETE ... FROM anon` (keeps INSERT). Even if a future policy were mistakenly permissive, the public key still can't read/edit.
3. **Validation CHECK constraints:**
   - `q1`–`q20`: integer 0–10, **and all 20 required** (rejects `q1=30000`, partial rows).
   - `q22_bible_days_per_week`: 0–7.
   - `q23`/`q24`/`q25`: pinned to their exact allowed option lists.
   - `q21_afterlife_belief`: length ≤ 300 (see Step B).
   - `reflection_lie_text` / `reflection_cost_text` / `reflection_step_text`: length ≤ 2000 each.
   - `top3_questions` / `reflection_avoids`: must be JSON arrays, ≤ 20 / ≤ 50 elements **and** size-capped (per-array serialized length), so a single element can't be a megabyte string.
4. **Retention** — enables `pg_cron` and schedules `purge_lying_survey_24mo` (weekly, Sun 03:00 UTC) deleting rows older than **24 months**.
5. **Rate-limit log table** (`submission_rate_log`) + the **`check_and_log_submission` RPC** (atomic check-and-reserve) used later by the Edge Function, plus a daily purge job. Stores an HMAC tag only — no raw IP.

> **Safe to run on live data.** The CHECK constraints are added `NOT VALID` (enforced immediately for new rows without scanning old ones), then validated in one reporting pass. If any existing row violates a constraint, that constraint is left `NOT VALID` (new rows still enforced) and a warning names it — clean that row and re-run to validate. No half-applied migration.

> Note: `pg_cron` may need enabling first at Dashboard → Database → Extensions. The SQL includes `create extension if not exists pg_cron;` but some orgs require enabling it via the UI.

### Step B — Decide `q21` validation
`q21_afterlife_belief` is currently **length-capped (≤300)** rather than pinned to its seven exact option strings, because that copy is long and gets reworded — exact-pinning means a future wording tweak silently rejects real submissions. If IT prefers strict pinning (like q23–q25), replace `chk_q21_len` with an `IN (...)` list of the exact seven strings. Tell us which and we'll supply the swap.

**Recommended longer-term (not changed here):** the cleanest fix is to submit a **stable code** for these single-choice answers (e.g. `afterlife_1`…`afterlife_7`) and let the page hold the display wording. Then the DB can strictly validate the code and copy edits never break submissions — the same principle applies to q23–q25. We left the current text-based design in place because switching requires a coordinated client + schema change and would reject in-flight submissions if done in isolation. Happy to do it as a planned follow-up.

### Step C — Cloudflare Turnstile keys
Create a Turnstile widget in the Cloudflare dashboard for the survey domain. You get a **site key** (public, goes in the page) and a **secret key** (goes in the function env). No cost for standard Turnstile. Set the widget's **allowed hostname** to the confirmed production hostname, and give it a stable `data-action` (e.g. `submit_survey`). The function verifies the Turnstile response's `hostname` (and `action`, if you set `TURNSTILE_EXPECTED_ACTION`), not just `success`, so a token solved on another site can't be replayed here.

### Step D — Deploy the Edge Function  *(adds rate-limiting)*
See `supabase/functions/submit-survey/README.md`. Summary:
```bash
supabase secrets set \
  TURNSTILE_SECRET=<secret> \
  ALLOWED_ORIGIN=https://foolingmyself.backtothebible.org \
  IP_HASH_PEPPER="$(openssl rand -hex 32)" \
  --project-ref kigvrcsuqrapharysogb
# Optional: TURNSTILE_EXPECTED_HOSTNAME (defaults to ALLOWED_ORIGIN host),
#           TURNSTILE_EXPECTED_ACTION (must match the widget's data-action).

# Deploy from the repo root so config.toml (verify_jwt = false) is applied.
supabase functions deploy submit-survey --project-ref kigvrcsuqrapharysogb
```
**`verify_jwt = false` is required** for this function (in `supabase/config.toml`, or add `--no-verify-jwt` to the deploy). The page calls it with no Authorization header, so with the default JWT gate on, Supabase would 401 the request before the code runs.

The function, in order: verifies Turnstile (`success` + hostname/action + timeout) → **atomically** reserves a per-IP rate-limit slot via `check_and_log_submission` (default 5/min; fail-closed 503 if the check can't run) → whitelists fields + validates types/ranges/sizes → inserts via service role. `ALLOWED_ORIGIN` is required (no `*` fallback). `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected automatically; the service role key never reaches the browser. The rate-limit identifier is an HMAC of the IP + date (with `IP_HASH_PEPPER`), not a raw or plainly-hashed IP.

### Step E — Cut the client over, then close the policy  *(clears permissive-policy finding)*
1. Add the Turnstile widget to the page; send its token to the function instead of posting directly to PostgREST. (Dev task — Claude can apply this on request.)
2. After verifying end-to-end, remove anon insert entirely:
```sql
drop policy if exists "anon can insert survey responses"
  on public.lying_to_myself_survey_responses;
revoke insert on public.lying_to_myself_survey_responses from anon;
```
After this, the public key can insert **nothing** — the permissive-policy finding is fully cleared.

### Step F — Old project
The old project `kddfedrklpavwjjdenor` still holds prior responses and its own (unreviewed) RLS. Decide: migrate historical data into Surveys, then decommission — or keep and review it under the same checklist. The older `lying-to-myself-survey` repo (personal) still points at it.

### Step G — Verify
Re-run the Supabase database linter and the RLS audit queries below; confirm findings cleared.

---

## 4. Verification / audit queries (for IT to run independently)

```sql
-- RLS is enabled (expect relrowsecurity = true)
select relname, relrowsecurity
from pg_class
where relname = 'lying_to_myself_survey_responses';

-- Policies: after Step A expect one INSERT policy for {anon};
-- after Step E expect NO anon policy at all.
select policyname, cmd, roles, qual, with_check
from pg_policies
where tablename = 'lying_to_myself_survey_responses';

-- Grants to anon: after Step A expect INSERT only; after Step E expect none.
select grantee, privilege_type
from information_schema.role_table_grants
where table_name = 'lying_to_myself_survey_responses' and grantee = 'anon';

-- CHECK constraints present (expect the chk_* constraints)
select conname, pg_get_constraintdef(oid)
from pg_constraint
where conrelid = 'public.lying_to_myself_survey_responses'::regclass
  and contype = 'c';

-- Retention job scheduled
select jobname, schedule, command from cron.job where jobname like 'purge_%';
```

A quick negative test IT can run with the **public anon key** (should fail after hardening):
```bash
# Should be rejected by CHECK constraint (q1 out of range) -> HTTP 400
curl -i -X POST \
  "https://kigvrcsuqrapharysogb.supabase.co/rest/v1/lying_to_myself_survey_responses" \
  -H "apikey: <ANON_KEY>" -H "Authorization: Bearer <ANON_KEY>" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" \
  -d '{"q1":30000}'

# Should be rejected by RLS/grant (no read) -> empty or 401/403
curl -i "https://kigvrcsuqrapharysogb.supabase.co/rest/v1/lying_to_myself_survey_responses?limit=1" \
  -H "apikey: <ANON_KEY>" -H "Authorization: Bearer <ANON_KEY>"
```

---

## 5. Mapping to IT's Item 2 observations

| IT observation | Resolved by | After which step |
|---|---|---|
| `WITH CHECK (true)` — arbitrary rows | CHECK constraints (mitigate) + drop anon insert (clear) | A (mitigate), E (clear) |
| `q1`–`q20` no range CHECK | `chk_core_scale_range` + `chk_core_complete` | A |
| `q22` no 0–7 bound | `chk_q22_range` | A |
| `q21/q23/q24/q25` accept any string | `chk_q23/24/25_values` (pinned); `chk_q21_len` (capped — see Step B) | A |
| free-text unbounded | `chk_reflection_len` (2000) | A |
| jsonb unbounded | `chk_top3_shape` / `chk_avoids_shape` | A |
| no rate-limiting | Turnstile + Edge Function per-IP throttle (atomic check-and-reserve, fail-closed) | C, D, E |
