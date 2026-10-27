/**
 * MINERVA — server-side authentication
 *
 * - PINs are stored as scrypt hashes with a per-user salt; comparison is timing-safe.
 * - A session is a random 32-byte token in an httpOnly, SameSite=Strict cookie.
 *   Only its SHA-256 is stored (user_session), so a leaked database can't be replayed.
 * - Failed sign-ins are counted per key over the last 15 minutes: 5 failures
 *   for one account from one address lock that pair for 15 minutes, so a stranger can't lock someone out from elsewhere;
 *   20 failures from one address lock the address; 50 failures on one account
 *   from anywhere lock the account (stored in app_user.locked_until, so it
 *   survives a restart).
 * - PIN reset is a demo (no e-mail/SMS): the code is returned to the caller. It is
 *   refused for administrator accounts; reset those with `npm run reset-pin`.
 * - Roles map to permission sets; requirePermission() guards routes.
 */
import crypto from 'crypto';
import { query, transaction } from '../db/pool.js';

export const SESSION_COOKIE = 'minerva_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const RESET_TTL_MS = 10 * 60 * 1000;
const MIN_PIN_LENGTH = 6;

export const ROLES = {
  admin: { label: 'Database Administrator', permissions: new Set(['view', 'sql', 'manage_users']) },
  inspector: { label: 'Mining Lease Inspector', permissions: new Set(['view']) },
  surveyor: { label: 'Geological Field Surveyor', permissions: new Set(['view']) },
  viewer: { label: 'Viewer', permissions: new Set(['view']) },
};

// Demo accounts inserted by db/setup.js (PINs are hashed on insert)
export const DEMO_USERS = [
  { username: 'USR-1024', display_name: 'Sidharth', role: 'admin', pin: 'minerva@2026' },
  { username: 'INS-4088', display_name: 'R. K. Sharma', role: 'inspector', pin: 'inspector@2026' },
  { username: 'GEO-9921', display_name: 'Ananya Sen', role: 'surveyor', pin: 'surveyor@2026' },
];

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

export function hashPin(pin, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(pin), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p }).toString('hex');
  return { hash, salt };
}

export function verifyPin(pin, hash, salt) {
  const candidate = Buffer.from(hashPin(pin, salt).hash, 'hex');
  const stored = Buffer.from(hash, 'hex');
  return candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored);
}

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

// ---------------------------------------------------------------------------
// Failed-attempt limiter: recent failure times per key, locked once `limit` is reached
// ---------------------------------------------------------------------------
function createLimiter({ limit, windowMs }) {
  const failures = new Map(); // key -> failure times within the window
  const locks = new Map(); // key -> locked until

  function check(key, now = Date.now()) {
    const recent = (failures.get(key) || []).filter((t) => t > now - windowMs);
    if (recent.length) failures.set(key, recent);
    else failures.delete(key);
    const until = locks.get(key) || 0;
    if (until > now) return { locked: true, retryAfterMs: until - now, attempts: recent.length };
    locks.delete(key);
    return { locked: false, retryAfterMs: 0, attempts: recent.length };
  }

  function record(key, now = Date.now()) {
    const recent = [...(failures.get(key) || []).filter((t) => t > now - windowMs), now];
    failures.set(key, recent);
    if (recent.length >= limit) locks.set(key, now + windowMs);
    // Drop keys with no recent failures and no active lock
    if (failures.size > 1000) [...failures.keys()].forEach((k) => check(k, now));
    return check(key, now);
  }

  function reset(key) {
    failures.delete(key);
    locks.delete(key);
  }

  return { limit, check, record, reset };
}

// ---------------------------------------------------------------------------
// Auth service bound to a database
// ---------------------------------------------------------------------------
export function createAuth() {
  const WINDOW = 15 * 60 * 1000;
  // username|address: the lock a normal user meets after 5 wrong PINs
  const userLimiter = createLimiter({ limit: 5, windowMs: WINDOW });
  // Per address the bar is higher: several people may share one network
  const ipLimiter = createLimiter({ limit: 20, windowMs: WINDOW });
  // One account attacked from many addresses
  const accountLimiter = createLimiter({ limit: 50, windowMs: WINDOW });
  // Reset codes requested per account (each request cancels the previous code)
  const resetLimiter = createLimiter({ limit: 3, windowMs: WINDOW });

  const q = {
    userByName: (name) => query('SELECT * FROM app_user WHERE lower(username) = lower($1)', [name]).then((r) => r.rows[0]),
    addSession: (...v) => query('INSERT INTO user_session (token_hash, user_id, created_at, expires_at, last_seen, ip) VALUES ($1, $2, $3, $4, $5, $6)', v),
    session: (hash) => query(`SELECT s.token_hash, s.expires_at, s.last_seen, u.user_id, u.username, u.display_name, u.role
      FROM user_session s JOIN app_user u ON u.user_id = s.user_id WHERE s.token_hash = $1`, [hash]).then((r) => r.rows[0]),
    deleteSession: (hash) => query('DELETE FROM user_session WHERE token_hash = $1', [hash]),
    deleteExpired: () => query('DELETE FROM user_session WHERE expires_at <= now()'),
    touch: (hash) => query('UPDATE user_session SET last_seen = now() WHERE token_hash = $1', [hash]),
    setFailures: (...v) => query('UPDATE app_user SET failed_attempts = $1, locked_until = $2 WHERE user_id = $3', v),
    audit: (...v) => query('INSERT INTO audit_log (user_id, username, action, detail, ip) VALUES ($1, $2, $3, $4, $5)', v),
    addReset: (...v) => query('INSERT INTO pin_reset (user_id, code_hash, expires_at) VALUES ($1, $2, $3)', v),
    latestReset: (userId) => query('SELECT * FROM pin_reset WHERE user_id = $1 AND NOT used ORDER BY reset_id DESC LIMIT 1', [userId]).then((r) => r.rows[0]),
    useReset: (userId, client) => query('UPDATE pin_reset SET used = TRUE WHERE user_id = $1 AND NOT used', [userId], client),
    resetAttempt: (id) => query('UPDATE pin_reset SET attempts = attempts + 1 WHERE reset_id = $1', [id]),
    knownIp: (userId, ip) => query("SELECT 1 FROM audit_log WHERE user_id = $1 AND action = 'login' AND ip = $2 LIMIT 1", [userId, ip]).then((r) => r.rowCount > 0),
  };

  const audit = (user, action, detail, ip) =>
    q.audit(user?.user_id ?? null, user?.username ?? null, action, detail ?? null, ip ?? null);

  const publicUser = (u) => ({
    id: u.user_id,
    username: u.username,
    name: u.display_name,
    role: u.role,
    roleLabel: ROLES[u.role]?.label || u.role,
    permissions: [...(ROLES[u.role]?.permissions || [])],
  });

  const pairKey = (username, ip) => `${username.toLowerCase()}|${ip}`;

  function lockState(username, ip, user) {
    const now = Date.now();
    const states = [userLimiter.check(pairKey(username, ip), now), ipLimiter.check(ip, now), accountLimiter.check(username.toLowerCase(), now)];
    // A lock written by an earlier run of the server still applies
    const stored = user?.locked_until ? new Date(user.locked_until).getTime() - now : 0;
    if (stored > 0) states.push({ locked: true, retryAfterMs: stored });
    const locked = states.filter((st) => st.locked);
    if (locked.length) return { locked: true, retryAfterMs: Math.max(...locked.map((st) => st.retryAfterMs)) };
    return { locked: false };
  }

  async function recordFailure(username, ip, user) {
    const now = Date.now();
    const pair = userLimiter.record(pairKey(username, ip), now);
    const byIp = ipLimiter.record(ip, now);
    const account = accountLimiter.record(username.toLowerCase(), now);
    if (user) {
      await q.setFailures(account.attempts, account.locked ? new Date(now + account.retryAfterMs) : null, user.user_id);
    }
    const locked = [pair, byIp, account].filter((st) => st.locked);
    if (locked.length) return { locked: true, retryAfterMs: Math.max(...locked.map((st) => st.retryAfterMs)) };
    return { locked: false, attemptsLeft: userLimiter.limit - pair.attempts };
  }

  return {
    publicUser,

    /** -> { ok, user, token, newIp } | { ok: false, status, error, retryAfterMs?, attemptsLeft? } */
    async login(username, pin, ip) {
      const name = String(username || '').trim();
      const user = name ? await q.userByName(name) : null;
      const lock = lockState(name, ip, user);
      if (lock.locked) {
        return { ok: false, status: 429, error: 'Too many failed attempts.', retryAfterMs: lock.retryAfterMs };
      }
      // Hash even for unknown users so response time doesn't reveal which usernames exist
      const valid = user ? verifyPin(pin, user.password_hash, user.password_salt) : (hashPin(String(pin || 'x')), false);
      if (!valid) {
        const s = await recordFailure(name || '(blank)', ip, user);
        await audit(user, 'login_failed', name, ip);
        if (s.locked) return { ok: false, status: 429, error: 'Too many failed attempts.', retryAfterMs: s.retryAfterMs };
        return { ok: false, status: 401, error: 'Wrong identifier or PIN.', attemptsLeft: s.attemptsLeft };
      }

      userLimiter.reset(pairKey(name, ip));
      await q.setFailures(0, null, user.user_id);
      const newIp = !(await q.knownIp(user.user_id, ip));
      const token = crypto.randomBytes(32).toString('base64url');
      const now = new Date();
      await q.addSession(sha256(token), user.user_id, now, new Date(now.getTime() + SESSION_TTL_MS), now, ip);
      await audit(user, 'login', null, ip);
      await q.deleteExpired();
      return { ok: true, user: publicUser(user), token, newIp, maxAgeMs: SESSION_TTL_MS };
    },

    /** User for a session token, or null */
    async sessionUser(token) {
      if (!token) return null;
      const key = sha256(token);
      const now = Date.now();
      const row = await q.session(key);
      if (!row) return null;
      if (new Date(row.expires_at).getTime() <= now) {
        await q.deleteSession(key);
        return null;
      }
      // Record activity at most once a minute per session
      if (now - new Date(row.last_seen).getTime() > 60 * 1000) await q.touch(key);
      return publicUser(row);
    },

    async logout(token) {
      if (!token) return;
      const key = sha256(token);
      const row = await q.session(key);
      await q.deleteSession(key);
      if (row) await audit(row, 'logout', null, null);
    },

    /** Demo PIN reset: the code is returned to the caller because no e-mail/SMS is sent */
    async requestReset(username, ip) {
      const name = String(username || '').trim();
      const locks = [ipLimiter.check(ip), resetLimiter.check(name.toLowerCase())].filter((st) => st.locked);
      if (locks.length) return { ok: false, status: 429, error: 'Too many reset requests.', retryAfterMs: Math.max(...locks.map((st) => st.retryAfterMs)) };
      ipLimiter.record(ip);
      resetLimiter.record(name.toLowerCase());
      const user = await q.userByName(name);
      // The demo hands out the code; never do that for an account that can run SQL
      if (user && ROLES[user.role]?.permissions.has('sql')) {
        return { ok: false, status: 403, error: 'Administrator PINs are reset on the server: npm run reset-pin -- <identifier>.' };
      }
      if (!user) return { ok: false, status: 404, error: 'No account with that identifier.' };
      const code = String(crypto.randomInt(100000, 1000000));
      await q.useReset(user.user_id);
      await q.addReset(user.user_id, sha256(code), new Date(Date.now() + RESET_TTL_MS));
      await audit(user, 'reset_requested', null, ip);
      return { ok: true, demoCode: code, expiresInMinutes: RESET_TTL_MS / 60000 };
    },

    async confirmReset(username, code, newPin, ip) {
      const user = await q.userByName(String(username || '').trim());
      const reset = user ? await q.latestReset(user.user_id) : null;
      if (!user || !reset) return { ok: false, status: 400, error: 'Request a new code first.' };
      if (new Date(reset.expires_at).getTime() <= Date.now()) return { ok: false, status: 400, error: 'That code has expired. Request a new one.' };
      if (reset.attempts >= 5) return { ok: false, status: 429, error: 'Too many wrong codes. Request a new one.' };
      if (sha256(String(code || '').trim()) !== reset.code_hash) {
        await q.resetAttempt(reset.reset_id);
        ipLimiter.record(ip);
        return { ok: false, status: 400, error: 'That code is not correct.' };
      }
      if (String(newPin || '').length < MIN_PIN_LENGTH) {
        return { ok: false, status: 400, error: `The new PIN must be at least ${MIN_PIN_LENGTH} characters.` };
      }
      const { hash, salt } = hashPin(newPin);
      // Signed out everywhere: old sessions must not survive a PIN change
      await transaction(async (client) => {
        await query('UPDATE app_user SET password_hash = $1, password_salt = $2, failed_attempts = 0, locked_until = NULL WHERE user_id = $3',
          [hash, salt, user.user_id], client);
        await q.useReset(user.user_id, client);
        await query('DELETE FROM user_session WHERE user_id = $1', [user.user_id], client);
      });
      accountLimiter.reset(user.username.toLowerCase());
      await audit(user, 'reset_completed', null, ip);
      return { ok: true };
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
export function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

export function sessionCookie(token, maxAgeMs) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}`;
}

export const clearedCookie = () => `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;

export function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}
