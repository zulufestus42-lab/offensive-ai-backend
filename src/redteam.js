// ---------------------------------------------------------------------------
// Red Team engagements: authorization, domain-ownership verification, the
// scope/approval GATE, and gated scan + report orchestration.
//
// The gate is the safety core: a scan can ONLY run when the engagement is
//   (1) ownership-verified (client proved they control the domain),
//   (2) human-approved (a reviewer approved it),
//   (3) the target is in scope, and
//   (4) the engagement isn't rejected/expired.
// The UI is never trusted for this — every scan request is checked here.
// ---------------------------------------------------------------------------
import { Router } from 'express';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import dns from 'node:dns/promises';
import { pool } from './db.js';
import { config } from './config.js';

// Admin token for review/approve actions. Falls back to the dashboard token.
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || config.dashboardToken;

// Supabase admin (for listing sign-ups). Service key is SECRET — server only.
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'zulufestus42@gmail.com')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

// Your FastAPI workers. Derived from SCANNER_URL unless overridden.
const base = (config.scannerUrl || '').replace(/\/v1\/scan\/?$/, '');
const CRAWLER_URL = process.env.CRAWLER_URL || (base ? `${base}/v1/crawler/scan` : '');
const REPORT_URL = process.env.REPORT_URL || (base ? `${base}/v1/report/generate` : '');

// Email (Resend) for human review of authorization requests.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const REVIEW_EMAIL = process.env.REVIEW_EMAIL || 'zulufestus42@gmail.com';
const RESEND_FROM = process.env.RESEND_FROM || 'Offensive AI <onboarding@resend.dev>';
// Absolute base for the approve/reject links in the email (falls back to the request host).
const PUBLIC_BASE = (process.env.PUBLIC_BASE || '').replace(/\/$/, '');

// ---- schema (self-migrating on import) ------------------------------------
const ready = pool
  .query(`
    CREATE TABLE IF NOT EXISTS engagements (
      id             BIGSERIAL PRIMARY KEY,
      created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      org_name       TEXT,
      domain         TEXT NOT NULL,
      scope_in       TEXT[] NOT NULL DEFAULT '{}',
      scope_out      TEXT[] NOT NULL DEFAULT '{}',
      signer_name    TEXT,
      signer_role    TEXT,
      signer_email   TEXT,
      contact_email  TEXT,
      intensity      TEXT NOT NULL DEFAULT 'safe',
      window_text    TEXT,
      verify_method  TEXT NOT NULL DEFAULT 'dns',
      verify_token   TEXT NOT NULL,
      ownership_verified BOOLEAN NOT NULL DEFAULT false,
      verified_at    TIMESTAMPTZ,
      review_status  TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
      reviewed_at    TIMESTAMPTZ,
      reviewer_note  TEXT,
      review_token   TEXT,
      pdf_name       TEXT
    );
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS review_token TEXT;
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS pdf_name TEXT;
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS pdf_base64 TEXT;
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS owner_id TEXT;
    CREATE TABLE IF NOT EXISTS scans (
      id            BIGSERIAL PRIMARY KEY,
      engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
      target        TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'running',     -- running | done | error
      started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      finished_at   TIMESTAMPTZ,
      forms_found   INT,
      note          TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id            BIGSERIAL PRIMARY KEY,
      scan_id       BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      url           TEXT,
      method        TEXT,
      parameter     TEXT,
      vuln_type     TEXT,
      severity      TEXT,
      evidence      TEXT,
      confidence    TEXT,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS reports (
      id            BIGSERIAL PRIMARY KEY,
      scan_id       BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      body_md       TEXT,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)
  .then(() => console.log('[redteam] schema ready'))
  .catch((e) => console.error('[redteam] schema error', e.message));

// ---- helpers ---------------------------------------------------------------
const token = () => `offai-${randomBytes(12).toString('hex')}`;
const safeEq = (a, b) => {
  if (!a || !b) return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
const bearer = (req) => (req.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
const requireAdmin = (req, res, next) => (safeEq(bearer(req), ADMIN_TOKEN) ? next() : res.status(401).json({ error: 'admin only' }));

// Identify the signed-in CUSTOMER from their Supabase access token (sent by the
// frontend). We validate it against Supabase rather than decoding locally, so no
// JWT secret is needed. Returns { sub, email, meta } or null (anonymous).
async function authUser(req) {
  const t = bearer(req);
  if (!t || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null;
  if (t === ADMIN_TOKEN) return null; // operator token is not a customer
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${t}` },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const u = await r.json();
    return { sub: u.id, email: u.email, meta: u.user_metadata || {} };
  } catch { return null; }
}

export const host = (s) => {
  if (!s) return '';
  try {
    return new URL(s.includes('://') ? s : `https://${s}`).hostname.toLowerCase();
  } catch {
    return String(s).toLowerCase().replace(/\/.*$/, '');
  }
};
const inList = (h, list) => (list || []).some((e) => {
  const x = host(e);
  return x && (h === x || h.endsWith(`.${x}`));
});

/** The GATE. Returns { ok } or { ok:false, reason }. */
export function gate(e, target) {
  if (!e) return { ok: false, reason: 'engagement not found' };
  if (!e.ownership_verified) return { ok: false, reason: 'domain ownership not verified' };
  if (e.review_status !== 'approved') return { ok: false, reason: `engagement is ${e.review_status}, not approved` };
  const h = host(target);
  if (!h) return { ok: false, reason: 'no target' };
  if (inList(h, e.scope_out)) return { ok: false, reason: `${h} is explicitly out of scope` };
  const allowed = inList(h, e.scope_in) || h === host(e.domain) || h.endsWith(`.${host(e.domain)}`);
  if (!allowed) return { ok: false, reason: `${h} is not in the authorized scope` };
  return { ok: true };
}

/** Verify the client controls the domain via a DNS TXT record. */
async function checkDnsOwnership(domain, tok) {
  const name = `_offai-verify.${host(domain)}`;
  try {
    const records = await dns.resolveTxt(name);
    const flat = records.map((r) => r.join('')).join(' ');
    return flat.includes(`offai-site-verification=${tok}`);
  } catch {
    return false;
  }
}

export async function getEngagement(id) {
  const { rows } = await pool.query('SELECT * FROM engagements WHERE id = $1', [id]);
  return rows[0] || null;
}

/**
 * Tenant isolation: may the caller act on this engagement?
 * Allowed when → the engagement is unowned (operator practice targets, e.g. Juice Shop),
 * OR the caller presents the admin/operator token, OR the signed-in customer IS the owner.
 * Everyone else (including customer B reaching for customer C's id) gets 403.
 * Returns { ok:true } or { ok:false, status, reason }.
 */
export async function authorizeOwner(req, e) {
  if (!e) return { ok: false, status: 404, reason: 'engagement not found' };
  if (!e.owner_id) return { ok: true };                       // unowned / sanctioned practice target
  if (safeEq(bearer(req), ADMIN_TOKEN)) return { ok: true };  // operator
  const user = await authUser(req);
  if (user && user.sub === e.owner_id) return { ok: true };   // the owning customer
  return { ok: false, status: 403, reason: 'not your engagement' };
}

const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// Email the authorization request to the human reviewer, with the signed PDF
// attached and one-click approve / reject links carrying a secret token.
async function sendReviewEmail({ engagement, pdfName, pdfBase64, origin }) {
  if (!RESEND_API_KEY) return { sent: false, reason: 'RESEND_API_KEY not set' };
  const root = PUBLIC_BASE || origin || '';
  const link = (d) =>
    `${root}/v1/redteam/engagements/${engagement.id}/decide?d=${d}&t=${engagement.review_token}`;
  const row = (k, v) => `<tr><td style="padding:4px 14px 4px 0;color:#8a8a8a">${esc(k)}</td><td style="padding:4px 0;color:#111">${esc(v) || '—'}</td></tr>`;
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#111">
      <div style="font-family:ui-monospace,monospace;font-size:12px;letter-spacing:.08em;color:#D92D20">OFFENSIVE AI · RED TEAM</div>
      <h2 style="margin:8px 0 4px;font-size:20px">Authorization request to review</h2>
      <p style="color:#555;font-size:14px;margin:0 0 18px">A client has requested authorization for active security testing. Review the attached signed authorization, then approve or reject below.</p>
      <table style="font-size:14px;border-collapse:collapse;margin-bottom:20px">
        ${row('Engagement', `#${engagement.id}`)}
        ${row('Organization', engagement.org_name)}
        ${row('Primary domain', engagement.domain)}
        ${row('Signer', `${engagement.signer_name || ''} ${engagement.signer_role ? '· ' + engagement.signer_role : ''}`)}
        ${row('Signer email', engagement.signer_email)}
        ${row('Testing window', engagement.window_text)}
        ${row('Intensity', engagement.intensity)}
        ${row('Ownership verified', engagement.ownership_verified ? 'yes' : 'not yet')}
      </table>
      <div>
        <a href="${link('approve')}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:12px 22px;border-radius:9px;margin-right:10px">Approve testing</a>
        <a href="${link('reject')}" style="display:inline-block;background:#fff;color:#D92D20;border:1px solid #E0B4AF;text-decoration:none;font-weight:600;font-size:14px;padding:12px 22px;border-radius:9px">Reject</a>
      </div>
      <p style="color:#999;font-size:12px;margin:20px 0 0">Approving only clears the human-review lock. A scan still runs only once domain ownership is verified too. This request is logged against engagement #${engagement.id}.</p>
    </div>`;

  const payload = {
    from: RESEND_FROM,
    to: [REVIEW_EMAIL],
    subject: `Red Team authorization — ${engagement.domain} (#${engagement.id})`,
    html,
  };
  if (pdfBase64) {
    const content = String(pdfBase64).replace(/^data:[^,]*,/, '');
    payload.attachments = [{ filename: pdfName || `authorization-${engagement.id}.pdf`, content }];
  }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) return { sent: false, reason: d?.message || `resend ${r.status}` };
    return { sent: true, id: d?.id };
  } catch (e) {
    return { sent: false, reason: e.message };
  }
}

// Minimal styled confirmation page for the email approve/reject links.
function decisionPage(title, message, ok = true) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(title)}</title>
  <div style="font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0A0A0A;color:#F2F2F2;margin:0">
    <div style="max-width:420px;padding:40px 32px;text-align:center">
      <div style="font-family:ui-monospace,monospace;font-size:12px;letter-spacing:.08em;color:${ok ? '#5AC47E' : '#E5484D'}">OFFENSIVE AI · RED TEAM</div>
      <h1 style="font-size:22px;margin:14px 0 8px">${esc(title)}</h1>
      <p style="color:#A3A3A3;font-size:14px;line-height:1.6;margin:0">${esc(message)}</p>
    </div>
  </div>`;
}

// ---- routes ----------------------------------------------------------------
export const redTeamRouter = Router();

// Create an engagement (from the B authorization form).
redTeamRouter.post('/engagements', async (req, res, next) => {
  try {
    await ready;
    const b = req.body ?? {};
    if (!b.domain) return res.status(400).json({ error: 'domain is required' });
    const vt = token();
    const rvt = token(); // secret token for the email approve/reject links
    const pdfName = b.pdfName ? String(b.pdfName).slice(0, 180) : null;
    const pdfB64 = b.pdfBase64 ? String(b.pdfBase64).slice(0, 8_000_000) : null; // store the signed PDF
    const user = await authUser(req); // the signed-in customer (owner), if any
    const org = b.orgName ?? (user && user.meta && (user.meta.org || user.meta.company)) ?? null;
    const { rows } = await pool.query(
      `INSERT INTO engagements
         (org_name, domain, scope_in, scope_out, signer_name, signer_role, signer_email,
          contact_email, intensity, window_text, verify_method, verify_token, review_token, pdf_name, pdf_base64, owner_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING id, domain, verify_method, verify_token, ownership_verified, review_status, created_at`,
      [
        org, host(b.domain),
        Array.isArray(b.scopeIn) ? b.scopeIn : (b.scopeIn ? String(b.scopeIn).split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : [host(b.domain)]),
        Array.isArray(b.scopeOut) ? b.scopeOut : (b.scopeOut ? String(b.scopeOut).split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : []),
        b.signerName ?? (user ? user.meta?.name : null) ?? null, b.signerRole ?? null, b.signerEmail ?? (user ? user.email : null) ?? null,
        b.contactEmail ?? b.signerEmail ?? (user ? user.email : null) ?? null, b.intensity ?? 'safe', b.window ?? null,
        b.verifyMethod ?? 'dns', vt, rvt, pdfName, pdfB64, user ? user.sub : null,
      ],
    );
    const e = rows[0];

    // Email the signed authorization to the human reviewer (never blocks on failure).
    const origin = `${req.protocol}://${req.get('host')}`;
    const emailResult = await sendReviewEmail({
      engagement: {
        id: e.id,
        domain: e.domain,
        review_token: rvt,
        org_name: b.orgName,
        signer_name: b.signerName,
        signer_role: b.signerRole,
        signer_email: b.signerEmail,
        window_text: b.window,
        intensity: b.intensity ?? 'safe',
        ownership_verified: false,
      },
      pdfName,
      pdfBase64: pdfB64,
      origin,
    });

    res.status(201).json({
      ...e,
      review_email: emailResult,
      verification: {
        method: 'dns',
        record: `_offai-verify.${e.domain}`,
        type: 'TXT',
        value: `offai-site-verification=${vt}`,
        instructions: `Add a DNS TXT record at _offai-verify.${e.domain} with the value "offai-site-verification=${vt}", then call verify.`,
      },
    });
  } catch (err) {
    next(err);
  }
});

// A customer's own engagements only (scoped by the signed-in owner).
redTeamRouter.get('/engagements/mine', async (req, res, next) => {
  try {
    await ready;
    const user = await authUser(req);
    if (!user) return res.status(401).json({ error: 'sign in required' });
    const { rows } = await pool.query(
      `SELECT id, domain, org_name, ownership_verified, review_status, created_at
         FROM engagements WHERE owner_id = $1 ORDER BY created_at DESC`, [user.sub]);
    res.json(rows);
  } catch (err) { next(err); }
});

// Status of one engagement (public-safe: no verify_token, no pdf bytes).
// Owner-scoped: if the engagement has an owner, only that owner may read it.
redTeamRouter.get('/engagements/:id', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    if (!e) return res.status(404).json({ error: 'not found' });
    if (e.owner_id) {
      const user = await authUser(req);
      if (!user || user.sub !== e.owner_id) return res.status(403).json({ error: 'not your engagement' });
    }
    const { verify_token, pdf_base64, ...safe } = e;
    res.json({ ...safe, has_pdf: !!pdf_base64 });
  } catch (err) {
    next(err);
  }
});

// Verify domain ownership.
redTeamRouter.post('/engagements/:id/verify', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    const own = await authorizeOwner(req, e);
    if (!own.ok) return res.status(own.status).json({ error: own.reason });
    if (e.ownership_verified) return res.json({ ownership_verified: true });
    const ok = await checkDnsOwnership(e.domain, e.verify_token);
    if (!ok) {
      return res.status(200).json({ ownership_verified: false, hint: `TXT record not found yet at _offai-verify.${e.domain}` });
    }
    await pool.query('UPDATE engagements SET ownership_verified = true, verified_at = now() WHERE id = $1', [e.id]);
    res.json({ ownership_verified: true });
  } catch (err) {
    next(err);
  }
});

// ---- admin: review queue + approve/reject ----------------------------------
redTeamRouter.get('/admin/engagements', requireAdmin, async (_req, res, next) => {
  try {
    await ready;
    const { rows } = await pool.query(
      `SELECT id, created_at, org_name, domain, signer_name, signer_role, signer_email,
              intensity, ownership_verified, review_status, reviewed_at,
              pdf_name, (pdf_base64 IS NOT NULL) AS has_pdf
       FROM engagements ORDER BY created_at DESC LIMIT 200`,
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Admin detail for one engagement (scope + signer + audit, no pdf bytes).
redTeamRouter.get('/admin/engagements/:id', requireAdmin, async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    if (!e) return res.status(404).json({ error: 'not found' });
    const { verify_token, pdf_base64, ...safe } = e;
    res.json({ ...safe, has_pdf: !!pdf_base64 });
  } catch (err) {
    next(err);
  }
});

// Serve the stored signed-authorization PDF to the admin dashboard.
// Accepts the admin token via Bearer OR ?t= (so it can be used in an <iframe>/<a>).
redTeamRouter.get('/admin/engagements/:id/authorization.pdf', async (req, res, next) => {
  try {
    await ready;
    const tok = bearer(req) || String(req.query.t || '');
    if (!safeEq(tok, ADMIN_TOKEN)) return res.status(401).json({ error: 'admin only' });
    const e = await getEngagement(req.params.id);
    if (!e || !e.pdf_base64) return res.status(404).json({ error: 'no authorization file on this engagement' });
    const b64 = String(e.pdf_base64).replace(/^data:[^,]*,/, '');
    const buf = Buffer.from(b64, 'base64');
    const name = (e.pdf_name || `authorization-${e.id}.pdf`).replace(/[^\w.\-]/g, '_');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${name}"`);
    res.send(buf);
  } catch (err) {
    next(err);
  }
});

redTeamRouter.post('/admin/engagements/:id/review', requireAdmin, async (req, res, next) => {
  try {
    await ready;
    const decision = String(req.body?.decision ?? '').toLowerCase();
    if (decision !== 'approve' && decision !== 'reject') return res.status(400).json({ error: 'decision must be approve or reject' });
    const status = decision === 'approve' ? 'approved' : 'rejected';
    const { rows } = await pool.query(
      'UPDATE engagements SET review_status = $1, reviewed_at = now(), reviewer_note = $2 WHERE id = $3 RETURNING id, domain, review_status',
      [status, req.body?.note ?? null, req.params.id],
    );
    if (!rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// Admin manual ownership verification — for sanctioned practice targets (e.g. OWASP
// Juice Shop) or verified-out-of-band cases. Recorded with a note for the audit trail.
redTeamRouter.post('/admin/engagements/:id/force-verify', requireAdmin, async (req, res, next) => {
  try {
    await ready;
    const { rows } = await pool.query(
      `UPDATE engagements SET ownership_verified = true, verified_at = now(),
         reviewer_note = COALESCE(reviewer_note,'') || $1 WHERE id = $2
       RETURNING id, domain, ownership_verified`,
      [` [manual-verify: ${String(req.body?.note ?? 'admin').slice(0, 200)}]`, req.params.id],
    );
    if (!rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// List the people who signed up (Supabase Auth admin API). Service key stays on
// the server. Returns { configured, users } — graceful when not yet configured.
redTeamRouter.get('/admin/users', requireAdmin, async (_req, res, next) => {
  try {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return res.json({ configured: false, users: [] });
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=200`, {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return res.json({ configured: true, users: [], error: `supabase ${r.status}` });
    const d = await r.json();
    const raw = Array.isArray(d) ? d : (d.users || []);
    const users = raw.map((u) => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      org: (u.user_metadata && (u.user_metadata.org || u.user_metadata.company)) || (u.email ? u.email.split('@')[1] : ''),
      role: ADMIN_EMAILS.includes((u.email || '').toLowerCase()) ? 'admin' : 'customer',
    }));
    res.json({ configured: true, users });
  } catch (err) { next(err); }
});

// Admin "Launch attack" — one atomic, operator-only call that prepares a
// sanctioned practice target (e.g. OWASP Juice Shop) ready to run: create-or-reuse
// the engagement for this domain, force-verify it, approve it, and audit it.
redTeamRouter.post('/admin/targets', requireAdmin, async (req, res, next) => {
  try {
    await ready;
    const domain = host(req.body?.domain);
    if (!domain) return res.status(400).json({ error: 'domain is required' });
    const scopeIn = Array.isArray(req.body?.scopeIn) && req.body.scopeIn.length
      ? req.body.scopeIn.map(host) : [domain];

    // Reuse an existing operator-owned (unowned) engagement for this domain if present.
    const found = await pool.query(
      `SELECT id FROM engagements WHERE domain = $1 AND owner_id IS NULL ORDER BY id DESC LIMIT 1`, [domain]);
    let eid = found.rows[0]?.id;
    if (!eid) {
      const ins = await pool.query(
        `INSERT INTO engagements (org_name, domain, scope_in, intensity, verify_method, verify_token, review_token)
         VALUES ($1,$2,$3,'safe','admin',$4,$5) RETURNING id`,
        [req.body?.orgName || 'Operator target', domain, scopeIn, token(), token()]);
      eid = ins.rows[0].id;
    } else {
      await pool.query(`UPDATE engagements SET scope_in = $2 WHERE id = $1`, [eid, scopeIn]);
    }
    await pool.query(
      `UPDATE engagements SET ownership_verified = true, verified_at = now(),
         review_status = 'approved', reviewed_at = now(),
         reviewer_note = COALESCE(reviewer_note,'') || $2 WHERE id = $1`,
      [eid, ` [admin target-launch ${new Date().toISOString()}]`]);
    const out = await getEngagement(eid);
    res.json({ id: out.id, domain: out.domain, ownership_verified: out.ownership_verified, review_status: out.review_status });
  } catch (err) { next(err); }
});

// One-click approve / reject from the review email. Auth is the per-engagement
// secret token in the link — not the admin bearer — so the reviewer can act
// straight from their inbox. Returns a human-readable confirmation page.
redTeamRouter.get('/engagements/:id/decide', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    if (!e) return res.status(404).type('html').send(decisionPage('Not found', 'This engagement no longer exists.', false));
    if (!e.review_token || !safeEq(String(req.query.t || ''), e.review_token)) {
      return res.status(403).type('html').send(decisionPage('Invalid link', 'This approval link is invalid or has already been superseded.', false));
    }
    const d = String(req.query.d || '').toLowerCase();
    if (d !== 'approve' && d !== 'reject') {
      return res.status(400).type('html').send(decisionPage('Unknown action', 'This link did not specify a valid decision.', false));
    }
    const status = d === 'approve' ? 'approved' : 'rejected';
    await pool.query(
      `UPDATE engagements SET review_status = $1, reviewed_at = now(),
         reviewer_note = COALESCE(reviewer_note,'') || $2 WHERE id = $3`,
      [status, ` [email-${status} ${new Date().toISOString()}]`, e.id],
    );
    const msg =
      status === 'approved'
        ? `Engagement #${e.id} for ${e.domain} is approved. Scanning will unlock once domain ownership is also verified.`
        : `Engagement #${e.id} for ${e.domain} is rejected. Scanning stays locked.`;
    res.type('html').send(decisionPage(status === 'approved' ? 'Approved' : 'Rejected', msg, status === 'approved'));
  } catch (err) {
    next(err);
  }
});

// ---- the gated scan --------------------------------------------------------
redTeamRouter.post('/engagements/:id/scan', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    const own = await authorizeOwner(req, e);
    if (!own.ok) return res.status(own.status).json({ error: own.reason });
    const target = host(req.body?.target || e?.domain);
    const g = gate(e, target);
    if (!g.ok) return res.status(403).json({ error: 'scan refused', reason: g.reason });
    if (!CRAWLER_URL) return res.status(500).json({ error: 'CRAWLER_URL not configured' });

    const { rows: sr } = await pool.query(
      'INSERT INTO scans (engagement_id, target, status) VALUES ($1,$2,$3) RETURNING id',
      [e.id, target, 'running'],
    );
    const scanId = sr[0].id;

    // Hand the authorized target to your FastAPI crawler.
    let data;
    try {
      const r = await fetch(CRAWLER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: `https://${target}` }),
        signal: AbortSignal.timeout(60_000),
      });
      data = await r.json();
    } catch (err) {
      await pool.query('UPDATE scans SET status = $1, finished_at = now(), note = $2 WHERE id = $3', ['error', err.message, scanId]);
      return res.status(502).json({ error: 'crawler unavailable', scanId });
    }

    const findings = Array.isArray(data?.FINDINGS) ? data.FINDINGS : [];
    for (const f of findings) {
      await pool.query(
        `INSERT INTO findings (scan_id, url, method, parameter, vuln_type, severity, evidence, confidence)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [scanId, f.PATH ?? null, f.METHOD ?? null, f.PARAMETER ?? null, f.VULNERABILITY_TYPE ?? null, f.SEVERITY ?? 'unrated', f.EVIDENCE ?? null, f.CONFIDENCE ?? null],
      );
    }
    await pool.query('UPDATE scans SET status = $1, finished_at = now(), forms_found = $2 WHERE id = $3', ['done', data?.TOTAL_FORMS_FOUND ?? null, scanId]);
    res.json({ scanId, target, findings: findings.length, raw: data });
  } catch (err) {
    next(err);
  }
});

// Latest findings for an engagement.
redTeamRouter.get('/engagements/:id/findings', async (req, res, next) => {
  try {
    await ready;
    const own = await authorizeOwner(req, await getEngagement(req.params.id));
    if (!own.ok) return res.status(own.status).json({ error: own.reason });
    const { rows } = await pool.query(
      `SELECT f.* FROM findings f
       JOIN scans s ON s.id = f.scan_id
       WHERE s.engagement_id = $1 ORDER BY f.created_at DESC LIMIT 500`,
      [req.params.id],
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Generate an LLM report + fixes for a scan (uses your FastAPI /v1/report/generate).
redTeamRouter.post('/scans/:scanId/report', async (req, res, next) => {
  try {
    await ready;
    if (!REPORT_URL) return res.status(500).json({ error: 'REPORT_URL not configured' });
    const { rows: srows } = await pool.query('SELECT engagement_id FROM scans WHERE id = $1', [req.params.scanId]);
    if (!srows[0]) return res.status(404).json({ error: 'scan not found' });
    const own = await authorizeOwner(req, await getEngagement(srows[0].engagement_id));
    if (!own.ok) return res.status(own.status).json({ error: own.reason });
    const { rows } = await pool.query('SELECT * FROM findings WHERE scan_id = $1', [req.params.scanId]);
    const r = await fetch(REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_results: { FINDINGS: rows } }),
      signal: AbortSignal.timeout(60_000),
    });
    const data = await r.json();
    const body = data?.AI_SECURITY_REPORT ?? '';
    await pool.query('INSERT INTO reports (scan_id, body_md) VALUES ($1,$2)', [req.params.scanId, body]);
    res.json({ scanId: req.params.scanId, report: body });
  } catch (err) {
    next(err);
  }
});
