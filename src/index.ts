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
  PASSWORD_PEPPER?: string;
  ADMIN_ORIGIN?: string;
  VAPID_PUBLIC_KEY?: string;
  WEB_PUSH_PRIVATE_KEY?: string;
  WEB_PUSH_SUBJECT?: string;
}

/** Build CORS+security headers for admin API responses */
function getAdminHeaders(origin: string, env: Env): Record<string, string> {
  const allowedOrigin = env.ADMIN_ORIGIN || 'https://admin.sunobolo.in';
  const isAllowed = origin && origin.includes(new URL(allowedOrigin).hostname);
  return {
    'access-control-allow-origin': isAllowed ? origin : allowedOrigin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization',
    'access-control-allow-credentials': 'true',
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    // CSP for API responses (JSON only — no scripts/styles needed)
    'content-security-policy': "default-src 'none'; frame-ancestors 'none';",
  };
}

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...(init.headers || {}),
    },
  });

const err = (msg: string, status = 400) => json({ error: msg }, { status });

/**
 * Require PASSWORD_PEPPER from env. Fail safely if not configured.
 * SECURITY: Never use hardcoded fallback secrets.
 * Migration: Set PASSWORD_PEPPER to the same value as the old hardcoded pepper
 * via `wrangler secret put` BEFORE deploying this code.
 */
function getPasswordPepper(env: Env): string {
  if (!env.PASSWORD_PEPPER) {
    console.error('[SECURITY] PASSWORD_PEPPER not configured — authentication will fail. Set via wrangler secret put.');
    throw new Error('Server configuration error. Please contact support.');
  }
  return env.PASSWORD_PEPPER;
}

async function hashToken(token: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token + secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password: string, pepper: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + pepper);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Check admin login rate limit: max 10 failed attempts per email per 15 minutes */
async function checkAdminLoginRateLimit(email: string, db: D1Database): Promise<boolean> {
  const fifteenMinAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const result = await db.prepare(
    `SELECT COUNT(*) as cnt FROM login_attempts WHERE phone = ? AND attempted_at > ? AND success = 0`
  ).bind(email, fifteenMinAgo).first<{ cnt: number }>();
  return (result?.cnt || 0) >= 10;
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
      return new Response(null, {
        headers: { ...getAdminHeaders(origin, env), 'max-age': '86400' },
      });
    }

    // CORS check
    const allowedOrigin = env.ADMIN_ORIGIN || 'https://admin.sunobolo.in';
    if (origin && !origin.includes(new URL(allowedOrigin).hostname)) {
      return err('CORS: origin not allowed', 403);
    }

    const headers = getAdminHeaders(origin, env);

    try {
      // ── Auth endpoints (no auth required) ──

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

        // Rate limit: max 10 failed admin login attempts per email per 15 minutes
        if (await checkAdminLoginRateLimit(body.email, env.DB)) {
          return err('Too many failed attempts. Please try again after 15 minutes.', 429);
        }

        const user = await env.DB.prepare('SELECT id, name, email, is_admin, password_hash FROM users WHERE email = ?').bind(body.email).first<{ id: string; name: string; email: string; is_admin: number; password_hash: string | null }>();
        if (!user || !user.is_admin) return err('Invalid credentials or not an admin account', 401);

        // Verify password
        if (!user.password_hash) return err('Admin password not set. Contact developer.', 403);
        const inputHash = await hashPassword(body.password, getPasswordPepper(env));
        if (inputHash !== user.password_hash) return err('Invalid password', 401);

        const sessionToken = crypto.randomUUID();
        if (!env.SESSION_SECRET) {
          console.error('[ADMIN] SESSION_SECRET not configured');
          return err('Server configuration error', 500);
        }
        const tokenHash = await hashToken(sessionToken, env.SESSION_SECRET);
        const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
        await env.DB.prepare('INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, tokenHash, expiresAt).run();
        const { password_hash: _, ...safeUser } = user;
        return new Response(JSON.stringify({ user: safeUser }), {
          status: 200,
          headers: { 'content-type': 'application/json', ...headers, 'set-cookie': `sb_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${90 * 24 * 60 * 60}` },
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
          headers: { 'content-type': 'application/json', 'access-control-allow-origin': allowedOrigin, 'set-cookie': 'sb_session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0' },
        });
      }

      // ── Admin data endpoints (auth required) ──
      const user = await authenticateAdmin(request, env);
      if (!user) return json({ error: 'Admin authentication required' }, { status: 401, headers });

      // GET /dashboard
      if (path === '/dashboard' && method === 'GET') {
        const range = url.searchParams.get('range') || 'all';
        let df = "date('now', '-100 years')";
        if (range === 'today') df = "date('now', 'start of day')";
        if (range === '7d') df = "date('now', '-7 days')";
        if (range === '30d') df = "date('now', '-30 days')";
        if (range === '3m') df = "date('now', '-3 months')";
        if (range === '6m') df = "date('now', '-6 months')";
        if (range === '1y') df = "date('now', '-1 year')";

        const [
          totalUsers, totalUsersInRange,
          activeSubs, expiredSubs,
          totalPayments, successPayments, failedPayments,
          totalRevenue,
          payingCustomers,
          recentPayments, recentActivity,
        ] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as n FROM users').first<{ n: number }>(),
          env.DB.prepare(`SELECT COUNT(*) as n FROM users WHERE created_at >= ${df}`).first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM subscriptions WHERE status = 'active'").first<{ n: number }>(),
          env.DB.prepare("SELECT COUNT(*) as n FROM subscriptions WHERE status = 'expired'").first<{ n: number }>(),
          env.DB.prepare('SELECT COUNT(*) as n FROM payments').first<{ n: number }>(),
          env.DB.prepare(`SELECT COUNT(*) as n FROM payments WHERE status = 'paid' AND created_at >= ${df}`).first<{ n: number }>(),
          env.DB.prepare(`SELECT COUNT(*) as n FROM payments WHERE status = 'failed' AND created_at >= ${df}`).first<{ n: number }>(),
          env.DB.prepare(`SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'paid' AND created_at >= ${df}`).first<{ total: number }>(),
          env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as n FROM payments WHERE status = 'paid' AND created_at >= ${df}`).first<{ n: number }>(),
          env.DB.prepare(`SELECT p.*, u.name, u.email, u.phone FROM payments p LEFT JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC LIMIT 20`).all(),
          env.DB.prepare('SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 30').all(),
        ]);

        const planStats = await env.DB.prepare(`SELECT package_id, COUNT(*) as count FROM subscriptions WHERE status = 'active' GROUP BY package_id`).all();
        const dailyRevenue = await env.DB.prepare(`SELECT date(created_at) as day, SUM(amount) as revenue, COUNT(*) as count FROM payments WHERE status = 'paid' AND created_at >= ${df} GROUP BY date(created_at) ORDER BY day`).all();
        const dailySignups = await env.DB.prepare(`SELECT date(created_at) as day, COUNT(*) as count FROM users WHERE created_at >= ${df} GROUP BY date(created_at) ORDER BY day`).all();

        const freeUsers = (totalUsers?.n || 0) - (payingCustomers?.n || 0);

        return json({
          totalUsers: totalUsers?.n || 0,
          newSignups: totalUsersInRange?.n || 0,
          activeSubscriptions: activeSubs?.n || 0,
          expiredSubscriptions: expiredSubs?.n || 0,
          totalPayments: totalPayments?.n || 0,
          successfulPayments: successPayments?.n || 0,
          failedPayments: failedPayments?.n || 0,
          totalRevenue: totalRevenue?.total || 0,
          payingCustomers: payingCustomers?.n || 0,
          freeUsers,
          recentPayments: recentPayments?.results || [],
          recentActivity: recentActivity?.results || [],
          planStats: planStats?.results || [],
          dailyRevenue: dailyRevenue?.results || [],
          dailySignups: dailySignups?.results || [],
        }, { headers });
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
        if (search) { where += ' AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
        if (filter === 'active') where += " AND s.status = 'active'";
        if (filter === 'expired') where += " AND s.status = 'expired'";
        if (filter === '3month') where += " AND s.package_id = 'three_month'";
        if (filter === '6month') where += " AND s.package_id = 'six_month'";
        if (filter === '1year') where += " AND s.package_id = 'one_year'";
        if (filter === 'free') where += " AND s.id IS NULL";
        const q = `SELECT u.id, u.name, u.email, u.phone, u.created_at, u.is_admin, u.last_login_at, s.package_id as plan, s.status as sub_status, s.started_at, s.expires_at FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id AND s.id = (SELECT id FROM subscriptions WHERE user_id = u.id ORDER BY expires_at DESC LIMIT 1) WHERE ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`;
        const { results } = await env.DB.prepare(q).bind(...params, limit, offset).all();
        const count = await env.DB.prepare(`SELECT COUNT(*) as n FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id WHERE ${where}`).bind(...params).first<{ n: number }>();
        return json({ members: results || [], total: count?.n || 0, page, limit }, { headers });
      }

      // GET /members/:id
      const memberMatch = path.match(/^\/members\/([\w-]+)$/);
      if (memberMatch && method === 'GET') {
        const uid = memberMatch[1];
        const mu = await env.DB.prepare('SELECT id, name, email, phone, avatar_color, is_admin, created_at, last_login_at, recovery_email FROM users WHERE id = ?').bind(uid).first();
        if (!mu) return err('Member not found', 404);
        const subs = await env.DB.prepare('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC').bind(uid).all();
        const pay = await env.DB.prepare('SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC').bind(uid).all();
        const prog = await env.DB.prepare('SELECT COUNT(*) as n FROM user_progress WHERE user_id = ?').bind(uid).first<{ n: number }>();
        const activity = await env.DB.prepare('SELECT * FROM audit_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').bind(uid).all();
        return json({ member: mu, subscriptions: subs?.results || [], payments: pay?.results || [], progressCount: prog?.n || 0, activity: activity?.results || [] }, { headers });
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
        if (search) { where += ' AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ? OR p.razorpay_payment_id LIKE ? OR p.razorpay_order_id LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`); }
        if (status === 'paid') where += " AND p.status = 'paid'";
        if (status === 'failed') where += " AND p.status = 'failed'";
        if (status === 'pending') where += " AND p.status = 'pending'";
        const q = `SELECT p.*, u.name, u.email, u.phone FROM payments p LEFT JOIN users u ON p.user_id = u.id WHERE ${where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?`;
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

      // ── Push Notification routes ──

      // GET /push/stats
      if (path === '/push/stats' && method === 'GET') {
        const [totalSubs, totalUsers, totalNotifs, totalSent] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as n FROM push_subscriptions').first<{ n: number }>(),
          env.DB.prepare('SELECT COUNT(*) as n FROM users').first<{ n: number }>(),
          env.DB.prepare('SELECT COUNT(*) as n FROM notifications').first<{ n: number }>(),
          env.DB.prepare("SELECT COALESCE(SUM(total_sent), 0) as n FROM notifications WHERE status = 'sent'").first<{ n: number }>(),
        ]);
        return json({
          subscriptions: totalSubs?.n || 0,
          totalUsers: totalUsers?.n || 0,
          notificationsSent: totalNotifs?.n || 0,
          totalPushesSent: totalSent?.n || 0,
        }, { headers });
      }

      // GET /notifications
      if (path === '/notifications' && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50'
        ).all();
        return json({ notifications: results || [] }, { headers });
      }

      // GET /notifications/:id/stats
      const notifStatsMatch = path.match(/^\/notifications\/([\w-]+)\/stats$/);
      if (notifStatsMatch && method === 'GET') {
        const nid = notifStatsMatch[1];
        const notif = await env.DB.prepare('SELECT * FROM notifications WHERE id = ?').bind(nid).first();
        if (!notif) return err('Notification not found', 404);
        const clicks = await env.DB.prepare('SELECT COUNT(*) as n FROM push_events WHERE notification_id = ? AND event_type = \"click\"').bind(nid).first<{ n: number }>();
        const closes = await env.DB.prepare('SELECT COUNT(*) as n FROM push_events WHERE notification_id = ? AND event_type = \"close\"').bind(nid).first<{ n: number }>();
        return json({ notification: notif, clicks: clicks?.n || 0, closes: closes?.n || 0 }, { headers });
      }

      // POST /notifications/send
      if (path === '/notifications/send' && method === 'POST') {
        const body = await request.json<{ title?: string; message?: string; cta_text?: string; cta_url?: string; type?: string; audience?: string }>();
        if (!body?.title || !body?.message) return err('Title and message required');

        // Anti-spam: Max 3 marketing per 24h
        const notifType = body.type || 'marketing';
        if (notifType === 'marketing') {
          const last24h = await env.DB.prepare(
            "SELECT COUNT(*) as cnt FROM notifications WHERE type = 'marketing' AND status = 'sent' AND sent_at > datetime('now', '-1 day')"
          ).first<{ cnt: number }>();
          if ((last24h?.cnt || 0) >= 3) {
            return err('Anti-spam limit: Maximum 3 marketing notifications per 24 hours.', 429);
          }
          const last7d = await env.DB.prepare(
            "SELECT COUNT(*) as cnt FROM notifications WHERE type = 'marketing' AND status = 'sent' AND sent_at > datetime('now', '-7 days')"
          ).first<{ cnt: number }>();
          if ((last7d?.cnt || 0) >= 10) {
            return err('Anti-spam limit: Maximum 10 marketing notifications per week.', 429);
          }
          const dup = await env.DB.prepare(
            "SELECT id FROM notifications WHERE title = ? AND message = ? AND status = 'sent' AND sent_at > datetime('now', '-1 hour')"
          ).bind(body.title, body.message).first();
          if (dup) return err('Duplicate notification sent in the last hour.', 409);
        }

        const notificationId = 'n_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        const audience = body.audience || 'all';

        // Build audience query
        let audienceQuery = 'SELECT DISTINCT ps.* FROM push_subscriptions ps JOIN users u ON ps.user_id = u.id';
        const conditions: string[] = [];
        if (audience === 'free') conditions.push("u.id NOT IN (SELECT user_id FROM subscriptions WHERE status = 'active')");
        else if (audience === 'paid') conditions.push("u.id IN (SELECT user_id FROM subscriptions WHERE status = 'active')");
        else if (audience === 'inactive_7d') conditions.push("u.last_login_at < datetime('now', '-7 days')");
        else if (audience === 'inactive_30d') conditions.push("u.last_login_at < datetime('now', '-30 days')");
        if (conditions.length > 0) audienceQuery += ' WHERE ' + conditions.join(' AND ');

        const { results: subscriptions } = await env.DB.prepare(audienceQuery).all();

        // Store notification
        await env.DB.prepare(
          'INSERT INTO notifications (id, title, message, cta_text, cta_url, type, audience, status, total_sent, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
        ).bind(notificationId, body.title, body.message, body.cta_text || 'Open', body.cta_url || '/', notifType, audience, 'sent', subscriptions?.length || 0).run();

        // Send web push
        let sent = 0;
        let failed = 0;
        const webPushSecret = env.WEB_PUSH_PRIVATE_KEY || '';
        const webPushSubject = env.WEB_PUSH_SUBJECT || 'https://sunobolo.in';

        if (webPushSecret) {
          for (const sub of (subscriptions || []) as any[]) {
            try {
              const pushPayload = JSON.stringify({
                title: body.title,
                body: body.message,
                icon: '/images/logo.png',
                badge: '/images/logo.png',
                data: { url: body.cta_url || '/', notification_id: notificationId },
                actions: body.cta_text ? [{ action: 'open', title: body.cta_text }] : [],
              });

              const response = await fetch(sub.endpoint, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/octet-stream',
                  'TTL': '86400',
                  'Urgency': 'normal',
                  'Authorization': webPushSecret,
                },
                body: pushPayload,
              });

              if (response.ok || response.status === 201) {
                sent++;
                await env.DB.prepare(
                  'INSERT INTO notification_log (id, notification_id, user_id, endpoint, status, sent_at) VALUES (?, ?, ?, ?, ?, datetime("now"))'
                ).bind('nl_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), notificationId, sub.user_id, sub.endpoint, 'sent').run();
              } else {
                failed++;
                if (response.status === 404 || response.status === 410) {
                  await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').bind(sub.endpoint).run();
                }
              }
            } catch {
              failed++;
            }
          }
        } else {
          failed = subscriptions?.length || 0;
        }

        return json({ ok: true, notificationId, total: subscriptions?.length || 0, sent, failed }, { headers });
      }

      // ── Coupon Management routes ──

      // GET /coupons — list all coupons
      if (path === '/coupons' && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT * FROM coupons ORDER BY created_at DESC'
        ).all();
        return json({ coupons: results || [] }, { headers });
      }

      // POST /coupons — create a new coupon
      if (path === '/coupons' && method === 'POST') {
        const body = await request.json<{
          code?: string; discount_type?: string; discount_value?: number;
          applicable_plans?: string; start_date?: string; expiry_date?: string;
          max_total_uses?: number; max_uses_per_user?: number;
          min_order_amount?: number; description?: string;
        }>();

        if (!body?.code || !body?.discount_type || body.discount_value === undefined || !body?.start_date || !body?.expiry_date) {
          return err('Missing required fields: code, discount_type, discount_value, start_date, expiry_date');
        }

        // Normalize code
        const code = body.code.toUpperCase().replace(/[^A-Z0-9]/g, '');
        if (code.length < 3 || code.length > 20) return err('Code must be 3-20 alphanumeric characters');
        if (!['percentage', 'fixed'].includes(body.discount_type)) return err('discount_type must be percentage or fixed');
        if (body.discount_type === 'percentage' && (body.discount_value < 1 || body.discount_value > 100)) {
          return err('Percentage must be between 1 and 100');
        }
        if (body.discount_type === 'fixed' && body.discount_value < 1) {
          return err('Fixed discount must be at least ₹1');
        }

        // Check duplicate code
        const existing = await env.DB.prepare('SELECT id FROM coupons WHERE code = ?').bind(code).first();
        if (existing) return err('A coupon with this code already exists', 409);

        const id = 'c_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        await env.DB.prepare(
          `INSERT INTO coupons (id, code, discount_type, discount_value, applicable_plans, start_date, expiry_date, max_total_uses, max_uses_per_user, min_order_amount, is_active, description)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
        ).bind(
          id, code, body.discount_type, body.discount_value,
          body.applicable_plans || 'all', body.start_date, body.expiry_date,
          body.max_total_uses || 0, body.max_uses_per_user || 1,
          body.min_order_amount || 0, body.description || null
        ).run();

        const coupon = await env.DB.prepare('SELECT * FROM coupons WHERE id = ?').bind(id).first();
        return json({ ok: true, coupon }, { headers, status: 201 });
      }

      // PUT /coupons/:id — update a coupon
      const couponUpdateMatch = path.match(/^\/coupons\/([\w-]+)$/);
      if (couponUpdateMatch && method === 'PUT') {
        const cid = couponUpdateMatch[1];
        const existingCoupon = await env.DB.prepare('SELECT * FROM coupons WHERE id = ?').bind(cid).first();
        if (!existingCoupon) return err('Coupon not found', 404);

        const body = await request.json<Record<string, unknown>>();
        const updates: string[] = [];
        const vals: unknown[] = [];

        if (body.code !== undefined) {
          const newCode = String(body.code).toUpperCase().replace(/[^A-Z0-9]/g, '');
          if (newCode.length < 3 || newCode.length > 20) return err('Code must be 3-20 alphanumeric characters');
          if (newCode !== existingCoupon.code) {
            const dup = await env.DB.prepare('SELECT id FROM coupons WHERE code = ? AND id != ?').bind(newCode, cid).first();
            if (dup) return err('A coupon with this code already exists', 409);
          }
          updates.push('code = ?'); vals.push(newCode);
        }
        if (body.discount_type !== undefined) { updates.push('discount_type = ?'); vals.push(body.discount_type); }
        if (body.discount_value !== undefined) { updates.push('discount_value = ?'); vals.push(body.discount_value); }
        if (body.applicable_plans !== undefined) { updates.push('applicable_plans = ?'); vals.push(body.applicable_plans); }
        if (body.start_date !== undefined) { updates.push('start_date = ?'); vals.push(body.start_date); }
        if (body.expiry_date !== undefined) { updates.push('expiry_date = ?'); vals.push(body.expiry_date); }
        if (body.max_total_uses !== undefined) { updates.push('max_total_uses = ?'); vals.push(body.max_total_uses); }
        if (body.max_uses_per_user !== undefined) { updates.push('max_uses_per_user = ?'); vals.push(body.max_uses_per_user); }
        if (body.min_order_amount !== undefined) { updates.push('min_order_amount = ?'); vals.push(body.min_order_amount); }
        if (body.is_active !== undefined) { updates.push('is_active = ?'); vals.push(body.is_active ? 1 : 0); }
        if (body.description !== undefined) { updates.push('description = ?'); vals.push(body.description); }

        if (updates.length === 0) return err('No fields to update');
        updates.push('updated_at = datetime("now")');
        vals.push(cid);

        await env.DB.prepare(`UPDATE coupons SET ${updates.join(', ')} WHERE id = ?`).bind(...vals).run();
        const updated = await env.DB.prepare('SELECT * FROM coupons WHERE id = ?').bind(cid).first();
        return json({ ok: true, coupon: updated }, { headers });
      }

      // DELETE /coupons/:id — soft delete (set inactive)
      const couponDeleteMatch = path.match(/^\/coupons\/([\w-]+)$/);
      if (couponDeleteMatch && method === 'DELETE') {
        const cid = couponDeleteMatch[1];
        const existingCoupon = await env.DB.prepare('SELECT id FROM coupons WHERE id = ?').bind(cid).first();
        if (!existingCoupon) return err('Coupon not found', 404);
        await env.DB.prepare('UPDATE coupons SET is_active = 0, updated_at = datetime("now") WHERE id = ?').bind(cid).run();
        return json({ ok: true }, { headers });
      }

      // GET /coupons/:id/stats — usage statistics
      const couponStatsMatch = path.match(/^\/coupons\/([\w-]+)\/stats$/);
      if (couponStatsMatch && method === 'GET') {
        const cid = couponStatsMatch[1];
        const coupon = await env.DB.prepare('SELECT * FROM coupons WHERE id = ?').bind(cid).first();
        if (!coupon) return err('Coupon not found', 404);

        const totalUsed = await env.DB.prepare(
          'SELECT COUNT(*) as n FROM coupon_usages WHERE coupon_id = ? AND status = ?'
        ).bind(cid, 'completed').first<{ n: number }>();

        const totalRevenue = await env.DB.prepare(
          'SELECT COALESCE(SUM(final_amount), 0) as total FROM coupon_usages WHERE coupon_id = ? AND status = ?'
        ).bind(cid, 'completed').first<{ total: number }>();

        const totalDiscountGiven = await env.DB.prepare(
          'SELECT COALESCE(SUM(discount_amount), 0) as total FROM coupon_usages WHERE coupon_id = ? AND status = ?'
        ).bind(cid, 'completed').first<{ total: number }>();

        const uniqueUsers = await env.DB.prepare(
          'SELECT COUNT(DISTINCT user_id) as n FROM coupon_usages WHERE coupon_id = ? AND status = ?'
        ).bind(cid, 'completed').first<{ n: number }>();

        const recentUsages = await env.DB.prepare(
          `SELECT cu.*, u.name, u.email FROM coupon_usages cu
           LEFT JOIN users u ON cu.user_id = u.id
           WHERE cu.coupon_id = ? AND cu.status = 'completed'
           ORDER BY cu.created_at DESC LIMIT 20`
        ).bind(cid).all();

        return json({
          coupon,
          usage: {
            totalUsed: totalUsed?.n || 0,
            remainingUses: (coupon as any).max_total_uses > 0 ? Math.max(0, (coupon as any).max_total_uses - (totalUsed?.n || 0)) : -1,
            totalRevenue: totalRevenue?.total || 0,
            totalDiscount: totalDiscountGiven?.total || 0,
            uniqueUsers: uniqueUsers?.n || 0,
          },
          recentUsages: recentUsages?.results || [],
        }, { headers });
      }

      return err('Not found', 404);
    } catch (e: any) {
      return json({ error: e.message || 'Server error' }, { status: 500, headers });
    }
  },
};
