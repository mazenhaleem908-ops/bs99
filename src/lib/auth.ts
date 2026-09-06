// Shared authentication helpers. Sessions are opaque random tokens stored server-side
// and delivered only in an HttpOnly cookie; they are never persisted in localStorage.

const DEFAULT_ADMINS = "";

export function adminEmails(): string[] {
  return (process.env["ADMIN_EMAILS"] || DEFAULT_ADMINS)
    .split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
}
export function isAdminEmail(email: string): boolean { return adminEmails().includes(email.trim().toLowerCase()); }
export function newToken(): string { return randomUrlSafe(48); }
export function randomUrlSafe(bytes = 32): string {
  const buf = new Uint8Array(bytes); crypto.getRandomValues(buf); return base64Url(buf);
}
export function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let str = ""; for (const byte of view) str += String.fromCharCode(byte);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export async function pkceChallenge(verifier: string): Promise<string> {
  return base64Url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
}
export function requestOrigin(request: Request): string {
  const configured = process.env["APP_ORIGIN"]?.trim().replace(/\/$/, "");
  if (configured) return configured;
  const url = new URL(request.url);
  return url.origin;
}
export function safeReturnTo(value: unknown): string {
  const raw = typeof value === "string" ? value : "";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/";
  return raw;
}

// One-time codes (email OTP and the Google hand-off code) are stored only as a
// SHA-256 digest, so a database/backup disclosure cannot replay a live code.
// Verification behaviour is unchanged: the same plaintext code still works.
export async function hashCode(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const SESSION_COOKIE = "bs_session";
export function sessionCookie(token: string): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`;
}
export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
export function cookieValue(request: Request, name: string): string | null {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

// Verify an OIDC JWT signature using the provider's JWKS. Only Google's
// issuer/JWKS are accepted by default; the JWKS URL is server-configurable for tests.
export async function verifyOidcJwt(jwt: string, clientId: string): Promise<Record<string, unknown> | null> {
  try {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(headerPart.replace(/-/g,"+").replace(/_/g,"/") + "=".repeat((4-headerPart.length%4)%4)), c=>c.charCodeAt(0)))) as { alg?: string; kid?: string };
  if (header.alg !== "RS256" || !header.kid) return null;
  const jwksUrl = process.env["GOOGLE_JWKS_URI"] || "https://www.googleapis.com/oauth2/v3/certs";
  const jwksRes = await fetch(jwksUrl, { headers: { accept: "application/json" } });
  if (!jwksRes.ok) return null;
  const jwks = (await jwksRes.json()) as { keys?: Array<Record<string, unknown>> };
  const jwk = jwks.keys?.find((k) => k['kid'] === header.kid && k['kty'] === "RSA" && k['alg'] === "RS256");
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const b64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/") + "=".repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
  const signingInput = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  if (!(await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, b64(signaturePart), signingInput))) return null;
  const claims = JSON.parse(new TextDecoder().decode(b64(payloadPart))) as Record<string, unknown>;
  const iss=String(claims["iss"]??"");
  const audClaim=claims["aud"]; const aud=Array.isArray(audClaim)?audClaim.map(String):[String(audClaim??"")];
  const exp=Number(claims["exp"]??0); const nbf=Number(claims["nbf"]??0);
  const azp=claims["azp"];
  const expectedIssuer=process.env["GOOGLE_ISSUER"]||"https://accounts.google.com";
  if(iss!==expectedIssuer && !(expectedIssuer==="https://accounts.google.com"&&iss==="accounts.google.com"))return null;
  if(!aud.includes(clientId)||!exp||exp*1000<=Date.now())return null;
  if(nbf && nbf*1000>Date.now()+30000)return null;
  if(azp && String(azp)!==clientId)return null;
  return claims;
  } catch { return null; }
}
