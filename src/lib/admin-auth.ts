// Shared admin/staff authorization. Every admin surface (the admin API and the
// older orders admin actions) resolves privileges here so role permissions are
// enforced identically and no staff account can bypass RBAC through a legacy route.
import { cookieValue, isAdminEmail, SESSION_COOKIE } from "./auth";

export type Role = "owner" | "finance" | "product" | "support" | "moderator";

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  owner: ["all"],
  finance: ["payments", "wallet", "order_status"],
  product: ["products", "promotions"],
  support: ["support", "order_status"],
  moderator: ["support", "order_status"],
};

export type AdminSession = {
  email: string;
  admin: true;
  role: Role;
  permissions: string[];
};

export function can(session: { permissions: string[] }, permission: string): boolean {
  return session.permissions.includes("all") || session.permissions.includes(permission);
}

type Sql = (strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown>;

/**
 * Resolves the admin session for a request, or null when the caller is not an
 * active owner/staff member. Owners come from ADMIN_EMAILS; staff come from
 * admin_staff and only receive the permissions of their role.
 */
export async function adminSessionFor(request: Request, sql: Sql): Promise<AdminSession | null> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || !process.env["DATABASE_URL"]) return null;

  const rows = (await sql`SELECT email, expires_at FROM auth_sessions WHERE token=${token} LIMIT 1`) as Array<{
    email: string;
    expires_at: string;
  }>;
  const row = rows[0];
  if (!row || new Date(row.expires_at).getTime() <= Date.now()) return null;

  const email = row.email.toLowerCase();
  if (isAdminEmail(email)) return { email, admin: true, role: "owner", permissions: ["all"] };

  let staff: Array<{ role: string; status: string }> = [];
  try {
    staff = (await sql`SELECT role, status FROM admin_staff WHERE lower(email)=${email} LIMIT 1`) as Array<{
      role: string;
      status: string;
    }>;
  } catch {
    return null; // admin_staff not provisioned: fail closed
  }
  const st = staff[0];
  if (!st || st.status !== "active" || !(st.role in ROLE_PERMISSIONS)) return null;
  const role = st.role as Role;
  return { email, admin: true, role, permissions: ROLE_PERMISSIONS[role] };
}
