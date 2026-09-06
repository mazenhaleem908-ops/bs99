# BloxStar — Security Audit (final)

## Verdict: READY FOR PRODUCTION (with the deployment prerequisites listed at the end)

## 1. Fixes applied in this pass

1. **Staff creation SQL** (`src/routes/api/public/admin.ts`) — the staff status was interpolated
   as an SQL identifier; it is now the text literal `'active'`. Staff creation works and stays
   parameterised.
2. **Admin permission gap in the legacy orders endpoint** (`src/routes/api/public/orders.ts`) —
   the old endpoint authorised on `ADMIN_EMAILS` only. All admin order actions now resolve
   through the shared RBAC helper `src/lib/admin-auth.ts`:
   - `confirm` requires the `payments` permission
   - `cancel` requires `order_status`
   - listing all orders requires `order_status`
   - owner (`ADMIN_EMAILS`) keeps `all`; disabled staff and expired sessions fail closed
   - requests with no session cookie are rejected before any database work
   Non-owner staff can no longer bypass the newer RBAC system on any order-status path.
3. **vercel.json** — verified present and correct for the TanStack Start / Nitro `vercel` preset
   (`framework: null`, `buildCommand: npm run build`, `outputDirectory: .vercel/output`) with
   production headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
   Permissions-Policy. Confirmed live on responses from the built app.
4. **One-time login codes hashed at rest** — email OTPs (`auth_codes`) and the Google OAuth
   handoff codes (`auth_login_codes`) are stored as SHA-256 digests, compared in constant time.
   User-visible authentication behaviour, code format and expiry are unchanged.
5. **Stored-XSS hardening** — the Roblox username saved with an order is now restricted to
   `A–Z a–z 0–9 _ . -` and space, so it cannot inject markup into the storefront/admin order
   tables that render it.

No products, prices, payment flows, business logic or UI were changed.

## 2. Verification performed

| Check | Result |
| --- | --- |
| `npm ci` | pass (409 packages) |
| `npm audit` (registry.npmjs.org) | 3 high transitive advisories found (brace-expansion, js-yaml, nanoid) → `npm audit fix` → **0 vulnerabilities** |
| `npm run typecheck` | pass (strict, `noPropertyAccessFromIndexSignature`) |
| `npm run build` | pass — `.vercel/output` + `dist/` generated |
| Routes | `/`, `/mm2`, `/adopt-me`, `/grow-a-garden`, `/roblox-items`, `/admin` → 200; `/auth/callback`, `/auth/google/start` → 302; unknown path → 404 |
| API endpoints | health 503 (no env in sandbox), session 401, orders 200/403, admin 403, wallet 503, email 401 — all correct unauthenticated behaviour |
| CSRF / cross-origin | every state-changing endpoint returns 403 for a foreign `Origin` |
| Secret scan | no private keys, DB URLs, Resend/Google/MoonPay secrets in source. Only the MoonPay **publishable** key `pk_live_…` in `public/storefront.html`, which is designed to be public. `.env*` is git-ignored. |

## 3. Security review by area

- **Authentication** — OTP: 6 digits, hashed at rest, single-use, expiring, rate limited.
  Sessions: opaque random tokens, HttpOnly + Secure + SameSite cookies, server-side expiry.
- **OAuth (Google)** — PKCE, `state` and `nonce` validated, ID token verified against Google JWKS
  with issuer/audience/expiry checks; handoff code single-use and hashed.
- **CSRF** — same-origin enforcement on all POST/PATCH endpoints (verified live).
- **RBAC** — single source of truth (`src/lib/admin-auth.ts`); roles owner/finance/product/support/
  moderator; staff lookup failures fail closed. Wallet admin operations remain owner-only.
- **IDOR / BOLA / data isolation** — customer queries are scoped by the session email; order codes
  alone never grant access; wallet reads/writes are keyed on the session email.
- **SQL injection** — all queries are parameterised Neon tagged templates; no string-built SQL
  remains (the staff `'active'` case was the last one).
- **XSS** — React escapes the admin UI; the storefront's server-derived fields are catalog data or
  now-sanitised usernames; CSP restricts script sources.
- **Payment manipulation** — prices, fees and totals are recomputed server-side from the catalog;
  MoonPay transactions are verified server-side before an order is marked paid.
- **Race conditions / stock / wallet** — stock reservation and every wallet mutation run inside
  atomic SQL functions with balance guards (`balance >= amount`), so double-spend and oversell are
  prevented at the database level.
- **Rate limiting** — distributed, database-backed, per IP and per identity on auth, wallet, order
  and email endpoints.

## 4. Deployment prerequisites (not code issues)

- Set `DATABASE_URL`, `RESEND_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `MOONPAY_SECRET_KEY`, `ADMIN_EMAILS` in Vercel. `/api/public/auth/health` returns 200 once set.
- Live third-party flows (real Neon database, real Google sign-in, real MoonPay payment) can only
  be exercised against production credentials; they were reviewed by code path, not executed here.
