/**
 * Vercel serverless health check: GET /api/health
 * Lightweight liveness/readiness probe. Returns no secrets and no user data.
 */
export const config = { runtime: "nodejs" };

export default function handler(_request: Request): Response {
  return new Response(
    JSON.stringify({
      status: "ok",
      service: "bloxstar",
      timestamp: new Date().toISOString(),
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    },
  );
}
