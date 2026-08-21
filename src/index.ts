/**
 * SunoBolo Admin API — Separate Cloudflare Worker
 *
 * Completely isolated from customer application.
 * CORS: only admin.sunobolo.in allowed.
 * Auth: server-side admin role verification.
 */

interface Env {
  DB: D1Database;
  SESSION_SECRET?: string;
  ADMIN_ORIGIN?: string;
}

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': init.headers?.['access-control-allow-origin'] || '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'content-type, authorization',
      'access-control-allow-credentials': 'true',
      ...(init.headers || {}),
    },
  });

const err = (msg: string, status = 400) => json({ error: msg }, { status });

const PASSWORD_PEPPER = 'sunobolo-secret-key-2024';

async function hashToken(token: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token + secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + PASSWORD_PEPPER);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function extractSessionToken(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(/sb_session=([^;]+)/);
  return match ? match[1] : null;
}

async function authenticateAdmin(request: Request, env: Env): Promise<{ id: string; name: string; email: string } | null> {
  const token = extractSessionToken(request.headers.get('cookie'));
  if (!token || !env.SESSION_SECRET) return null;

  const tokenHash = await hashToken(token, env.SESSION_SECRET);
  const session = await env.DB.prepare(
    `SELECT s.user_id, s.expires_at FROM sessions s WHERE s.token_hash = ?`
  ).bind(tokenHash).first<{ user_id: string; expires_at: string }>();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) return null;

  const user = await env.DB.prepare(
    `SELECT id, name, email, is_admin FROM users WHERE id = ?`
  ).bind(session.user_id).first<{ id: string; name: string; email: string; is_admin: number }>();

  if (!user || !user.is_admin) return null;
  return user;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/admin/, '');
    const method = request.method.toUpperCase();
    const origin = request.headers.get('origin') || '';

    // CORS preflight
    if (method === 'OPTIONS') {
      const allowed = env.ADMIN_ORIGIN || 'https://admin.sunobolo.in';
      return new Response(null, {
        headers: {
          'access-control-allow-origin': allowed,
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type, authorization',
          'access-control-allow-credentials': 'true',
          'max-age': '86400',
        },
      });
    }

    // CORS check
    const allowedOrigin = env.ADMIN_ORIGIN || 'https://admin.sunobolo.in';
    if (origin && !origin.includes(new URL(allowedOrigin).hostname)) {
      return err('CORS: origin not allowed', 403);
    }

    // Auth check
    const user = await authenticateAdmin(request, env);
    if (!user) return json({ error: 'Admin authentication required' }, { status: 401, headers: { 'access-control-allow-origin': allowedOrigin, 'access-control-allow-credentials': 'true' } });

    const headers = { 'access-control-allow-origin': allowedOrigin, 'access-control-allow-credentials': 'true' };

    try {
      // ── Auth endpoints (admin-only login) ──

      // GET /auth/me
      if (path === '/auth/me' && method === 'GET') {
        const token = extractSessionToken(request.headers.get('cookie'));
        if (!token || !env.SESSION_SECRET) return json({ user: null }, { headers });
        const tokenHash = await hashToken(token, env.SESSION_SECRET);
        const session = await env.DB.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?').bind(tokenHash).first<{ user_id: string; expires_at: string }>();
        if (!session || new Date(session.expires_at) < new Date()) return json({ user: null }, { headers });
        const u = await env.DB.prepare('SELECT id, name, email, is_admin FROM users WHERE id = ?').bind(session.user_id).first();
        if (!u || !u.is_admin) return json({ user: null }, { headers });
        return json({ user: u }, { headers });
      }

      // POST /auth/login
      if (path === '/auth/login' && method === 'POST') {
        const body = await request.json<{ email?: string; password?: string }>();
        if (!body?.email || !body?.password) return err('Email and password required');

        const user = await env.DB.prepare('SELECT id, name, email, is_admin, password_hash FROM users WHERE email = ?').bind(body.email).first<{ id: string; name: string; email: string; is_admin: number; password_hash: string | null }>();
        if (!user || !user.is_admin) return err('Invalid credentials or not an admin account', 401);

        // Verify password
        if (!user.password_hash) return err('Admin password not set. Contact developer.', 403);
        const inputHash = await hashPassword(body.password);
        if (inputHash !== user.password_hash) return err('Invalid password', 401);

        const sessionToken = crypto.randomUUID();
        const tokenHash = await hashToken(sessionToken, env.SESSION_SECRET || 'default-secret');
        const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
        await env.DB.prepare('INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, tokenHash, expiresAt).run();
        return new Response(JSON.stringify({ user }), {
          status: 200,
          headers: { 'content-type': 'application/json', 'access-control-allow-origin': allowedOrigin, 'access-control-allow-credentials': 'true', 'set-cookie': `sb_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${90 * 24 * 60 * 60}` },
        });
      }

      // POST /auth/logout
      if (path === '/auth/logout' && method === 'POST') {
        const token = extractSessionToken(request.headers.get('cookie'));
        if (token && env.SESSION_SECRET) {
          const tokenHash = await hashToken(token, env.SESSION_SECRET);
          await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json', 'access-control-allow-origin': allowedOrigin, 'set-cookie': 'sb_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' },
        });
      }

      // ── Admin data endpoints ──

      // GET /dashboard
      if (path === '/dashboard' && method === 'GET') {
        const [totalUsers, activeSubs, expiredSubs, totalPayments, successPayments, failedPayments, totalRevenue, recentPayments] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as n FROM users').first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM subscriptions WHERE status = 'active'").first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM subscriptions WHERE status = 'expired'").first<{ n: number }>(),
          env.DB.prepare('SELECT COUNT(*) as n FROM payments').first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM payments WHERE status = 'paid'").first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM payments WHERE status = 'failed'").first<{ n: number }>(),
          env.DB.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'paid'").first<{ total: number }>(),
          env.DB.prepare(`SELECT p.*, u.name, u.email FROM payments p LEFT JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC LIMIT 20`).all(),
        ]);
        const planStats = await env.DB.prepare(`SELECT package_id, COUNT(*) as count FROM subscriptions WHERE status = 'active' GROUP BY package_id`).all();
        const dailyRevenue = await env.DB.prepare(`SELECT date(created_at) as day, SUM(amount) as revenue, COUNT(*) as count FROM payments WHERE status = 'paid' AND created_at >= date('now', '-30 days') GROUP BY date(created_at) ORDER BY day`).all();
        return json({ totalUsers: totalUsers?.n || 0, activeSubscriptions: activeSubs?.n || 0, expiredSubscriptions: expiredSubs?.n || 0, totalPayments: totalPayments?.n || 0, successfulPayments: successPayments?.n || 0, failedPayments: failedPayments?.n || 0, totalRevenue: totalRevenue?.total || 0, recentPayments: recentPayments?.results || [], planStats: planStats?.results || [], dailyRevenue: dailyRevenue?.results || [] }, { headers });
      }

      // GET /members
      if (path === '/members' && method === 'GET') {
        const search = url.searchParams.get('search') || '';
        const filter = url.searchParams.get('filter') || 'all';
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = 20;
        const offset = (page - 1) * limit;
        let where = '1=1';
        const params: string[] = [];
        if (search) { where += ' AND (u.name LIKE ? OR u.email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
        if (filter === 'active') where += " AND s.status = 'active'";
        if (filter === 'expired') where += " AND s.status = 'expired'";
        if (filter === 'google') where += " AND u.google_id IS NOT NULL";
        if (filter === '3month') where += " AND s.package_id = 'three_month'";
        if (filter === '6month') where += " AND s.package_id = 'six_month'";
        if (filter === '1year') where += " AND s.package_id = 'one_year'";
        const q = `SELECT u.id, u.name, u.email, u.created_at, u.is_admin, u.google_id, s.package_id as plan, s.status as sub_status, s.started_at, s.expires_at FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id AND s.id = (SELECT id FROM subscriptions WHERE user_id = u.id ORDER BY expires_at DESC LIMIT 1) WHERE ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`;
        const { results } = await env.DB.prepare(q).bind(...params, limit, offset).all();
        const count = await env.DB.prepare(`SELECT COUNT(*) as n FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id WHERE ${where}`).bind(...params).first<{ n: number }>();
        return json({ members: results || [], total: count?.n || 0, page, limit }, { headers });
      }

      // GET /members/:id
      const memberMatch = path.match(/^\/members\/([\w-]+)$/);
      if (memberMatch && method === 'GET') {
        const uid = memberMatch[1];
        const mu = await env.DB.prepare('SELECT id, name, email, phone, avatar_color, is_admin, created_at, google_id FROM users WHERE id = ?').bind(uid).first();
        if (!mu) return err('Member not found', 404);
        const subs = await env.DB.prepare('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC').bind(uid).all();
        const pay = await env.DB.prepare('SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC').bind(uid).all();
        const prog = await env.DB.prepare('SELECT COUNT(*) as n FROM user_progress WHERE user_id = ?').bind(uid).first<{ n: number }>();
        return json({ member: mu, subscriptions: subs?.results || [], payments: pay?.results || [], progressCount: prog?.n || 0 }, { headers });
      }

      // GET /payments
      if (path === '/payments' && method === 'GET') {
        const search = url.searchParams.get('search') || '';
        const status = url.searchParams.get('status') || 'all';
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = 20;
        const offset = (page - 1) * limit;
        let where = '1=1';
        const params: string[] = [];
        if (search) { where += ' AND (u.name LIKE ? OR u.email LIKE ? OR p.razorpay_payment_id LIKE ? OR p.razorpay_order_id LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`); }
        if (status === 'paid') where += " AND p.status = 'paid'";
        if (status === 'failed') where += " AND p.status = 'failed'";
        if (status === 'pending') where += " AND p.status = 'pending'";
        const q = `SELECT p.*, u.name, u.email FROM payments p LEFT JOIN users u ON p.user_id = u.id WHERE ${where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?`;
        const { results } = await env.DB.prepare(q).bind(...params, limit, offset).all();
        const count = await env.DB.prepare(`SELECT COUNT(*) as n FROM payments p LEFT JOIN users u ON p.user_id = u.id WHERE ${where}`).bind(...params).first<{ n: number }>();
        const summary = await env.DB.prepare(`SELECT COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) as revenue, COUNT(CASE WHEN status='paid' THEN 1 END) as success, COUNT(CASE WHEN status='failed' THEN 1 END) as failed, COUNT(CASE WHEN status='pending' THEN 1 END) as pending FROM payments`).first();
        return json({ payments: results || [], total: count?.n || 0, page, limit, summary }, { headers });
      }

      // GET /reports
      if (path === '/reports' && method === 'GET') {
        const range = url.searchParams.get('range') || '30d';
        let df = "date('now', '-30 days')";
        if (range === '7d') df = "date('now', '-7 days')";
        if (range === '1m') df = "date('now', '-1 month')";
        if (range === 'all') df = "date('now', '-100 years')";
        const [rev, plan, users, courses, ae] = await Promise.all([
          env.DB.prepare(`SELECT date(created_at) as day, SUM(amount) as revenue, COUNT(*) as count FROM payments WHERE status = 'paid' AND created_at >= ${df} GROUP BY date(created_at) ORDER BY day`).all(),
          env.DB.prepare(`SELECT package_id, COUNT(*) as count, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active FROM subscriptions GROUP BY package_id`).all(),
          env.DB.prepare(`SELECT date(created_at) as day, COUNT(*) as count FROM users WHERE created_at >= ${df} GROUP BY date(created_at) ORDER BY day`).all(),
          env.DB.prepare(`SELECT c.title, c.emoji, COUNT(up.id) as completions FROM user_progress up JOIN sentences s ON up.sentence_id = s.id JOIN lessons l ON s.lesson_id = l.id JOIN courses c ON l.course_id = c.id GROUP BY c.id ORDER BY completions DESC LIMIT 5`).all(),
          env.DB.prepare(`SELECT status, COUNT(*) as count FROM subscriptions GROUP BY status`).all(),
        ]);
        return json({ revenueByDay: rev?.results || [], subsByPlan: plan?.results || [], newUsers: users?.results || [], topCourses: courses?.results || [], activevsExpired: ae?.results || [] }, { headers });
      }

      return err('Not found', 404);
    } catch (e: any) {
      return json({ error: e.message || 'Server error' }, { status: 500, headers });
    }
  },
};
