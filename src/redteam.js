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

// Your FastAPI workers. Derived from SCANNER_URL unless overridden.
const base = (config.scannerUrl || '').replace(/\/v1\/scan\/?$/, '');
const CRAWLER_URL = process.env.CRAWLER_URL || (base ? `${base}/v1/crawler/scan` : '');
const REPORT_URL = process.env.REPORT_URL || (base ? `${base}/v1/report/generate` : '');

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
      reviewer_note  TEXT
    );
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

const host = (s) => {
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
function gate(e, target) {
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

async function getEngagement(id) {
  const { rows } = await pool.query('SELECT * FROM engagements WHERE id = $1', [id]);
  return rows[0] || null;
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
    const { rows } = await pool.query(
      `INSERT INTO engagements
         (org_name, domain, scope_in, scope_out, signer_name, signer_role, signer_email,
          contact_email, intensity, window_text, verify_method, verify_token)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING id, domain, verify_method, verify_token, ownership_verified, review_status, created_at`,
      [
        b.orgName ?? null, host(b.domain),
        Array.isArray(b.scopeIn) ? b.scopeIn : (b.scopeIn ? String(b.scopeIn).split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : [host(b.domain)]),
        Array.isArray(b.scopeOut) ? b.scopeOut : (b.scopeOut ? String(b.scopeOut).split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : []),
        b.signerName ?? null, b.signerRole ?? null, b.signerEmail ?? null,
        b.contactEmail ?? b.signerEmail ?? null, b.intensity ?? 'safe', b.window ?? null,
        b.verifyMethod ?? 'dns', vt,
      ],
    );
    const e = rows[0];
    res.status(201).json({
      ...e,
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

// Status of one engagement.
redTeamRouter.get('/engagements/:id', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    if (!e) return res.status(404).json({ error: 'not found' });
    const { verify_token, ...safe } = e;
    res.json(safe);
  } catch (err) {
    next(err);
  }
});

// Verify domain ownership.
redTeamRouter.post('/engagements/:id/verify', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    if (!e) return res.status(404).json({ error: 'not found' });
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
              ownership_verified, review_status, reviewed_at
       FROM engagements ORDER BY created_at DESC LIMIT 200`,
    );
    res.json(rows);
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

// ---- the gated scan --------------------------------------------------------
redTeamRouter.post('/engagements/:id/scan', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
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
