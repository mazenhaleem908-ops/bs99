// Per-account key/value store so a signed-in customer sees the same data
// (profile, wishlist, promo codes, preferences) on every device.
//
// The storefront used to keep this in localStorage only, so signing in from
// another device looked like a brand new account. Values now live in the
// database keyed by the signed-in email, and each entry carries the client
// timestamp so the newest write wins when two devices disagree.
import { createFileRoute } from "@tanstack/react-router";
import { cookieValue, SESSION_COOKIE, isAdminEmail } from "@/lib/auth";
import { jsonResponse, preflight, safeHandler, sameOrigin } from "@/lib/http";
import { clientIp, distributedRateLimit } from "@/lib/rate-limit";

const MAX_KEYS = 60;
const MAX_KEY_LEN = 120;
const MAX_VALUE_LEN = 120_000;
const MAX_PAYLOAD = 400_000;

const database = async () => (await import("@/lib/db")).db();
type Sql = Awaited<ReturnType<typeof database>>;
type Session = { email: string; admin: boolean } | null;
type Entry = { v: string; t: number };
type Bag = Record<string, Entry>;

async function sessionFor(sql: Sql, request: Request): Promise<Session> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  const rows = (await sql`SELECT email,expires_at FROM auth_sessions WHERE token=${token} LIMIT 1`) as Array<{
    email: string;
    expires_at: string;
  }>;
  const row = rows[0];
  if (!row || new Date(row.expires_at).getTime() < Date.now()) return null;
  return { email: row.email.toLowerCase(), admin: isAdminEmail(row.email) };
}

async function ensureSchema(sql: Sql) {
  await sql`CREATE TABLE IF NOT EXISTS user_data(
    email text PRIMARY KEY,
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`;
}

async function bagOf(sql: Sql, email: string): Promise<Bag> {
  const rows = (await sql`SELECT data FROM user_data WHERE email=${email} LIMIT 1`) as Array<{ data: unknown }>;
  const raw = rows[0]?.data;
  return raw && typeof raw === "object" ? (raw as Bag) : {};
}

function sanitize(input: unknown): Bag {
  const out: Bag = {};
  if (!input || typeof input !== "object") return out;
  let count = 0;
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (count >= MAX_KEYS) break;
    if (!key || key.length > MAX_KEY_LEN) continue;
    if (!value || typeof value !== "object") continue;
    const v = (value as { v?: unknown }).v;
    const t = Number((value as { t?: unknown }).t);
    if (typeof v !== "string" || v.length > MAX_VALUE_LEN) continue;
    out[key] = { v, t: Number.isFinite(t) && t > 0 ? Math.min(t, Date.now() + 60_000) : Date.now() };
    count += 1;
  }
  return out;
}

function merge(current: Bag, incoming: Bag): Bag {
  const next: Bag = { ...current };
  for (const [key, entry] of Object.entries(incoming)) {
    const existing = next[key];
    if (!existing || Number(existing.t || 0) <= entry.t) next[key] = entry;
  }
  // Keep the stored bag bounded: newest keys win.
  const keys = Object.keys(next);
  if (keys.length > MAX_KEYS) {
    keys
      .sort((a, b) => Number(next[b]?.t || 0) - Number(next[a]?.t || 0))
      .slice(MAX_KEYS)
      .forEach((k) => delete next[k]);
  }
  return next;
}

export const Route = createFileRoute("/api/public/userdata")({
  server: {
    handlers: {
      OPTIONS: async ({ request }) => preflight(request),
      POST: async ({ request }) =>
        safeHandler(request, "userdata", async () => {
          const json = (b: unknown, s = 200) => jsonResponse(request, b, s);
          if (!sameOrigin(request)) return json({ ok: false, error: "forbidden" }, 403);

          let text: string;
          try {
            text = await request.text();
          } catch {
            return json({ ok: false, error: "bad_request" }, 400);
          }
          if (text.length > MAX_PAYLOAD) return json({ ok: false, error: "too_large" }, 413);
          let body: Record<string, unknown>;
          try {
            body = JSON.parse(text || "{}") as Record<string, unknown>;
          } catch {
            return json({ ok: false, error: "bad_request" }, 400);
          }

          if (!process.env["DATABASE_URL"]) return json({ ok: false, error: "unavailable" }, 503);
          const { ensureAuthSchema } = await import("@/lib/db");
          await ensureAuthSchema();
          const sql = await database();
          await ensureSchema(sql);
          const session = await sessionFor(sql, request);
          if (!session) return json({ ok: false, error: "unauthorized" }, 401);
          if (!(await distributedRateLimit(sql, `userdata:${clientIp(request)}:${session.email}`, 90, 60_000)))
            return json({ ok: false, error: "rate_limited" }, 429);

          const email = session.email;
          const action = String(body["action"] ?? "get").toLowerCase();

          if (action === "get") return json({ ok: true, email, entries: await bagOf(sql, email) });

          if (action === "set") {
            const incoming = sanitize(body["entries"]);
            if (!Object.keys(incoming).length)
              return json({ ok: true, email, entries: await bagOf(sql, email) });
            const merged = merge(await bagOf(sql, email), incoming);
            await sql`INSERT INTO user_data(email,data) VALUES(${email},${JSON.stringify(merged)}::jsonb)
              ON CONFLICT(email) DO UPDATE SET data=${JSON.stringify(merged)}::jsonb, updated_at=now()`;
            return json({ ok: true, email, entries: merged });
          }

          return json({ ok: false, error: "unknown_action" }, 400);
        }),
    },
  },
});
