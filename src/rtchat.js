// rtchat.js — Engagement-scoped Red Team chatbot.
// This is NOT the SOC traffic analyst. It is the AI operator that ran THIS
// pentest, answering questions about THIS engagement only: what it attacked,
// what bypassed the firewall, what it hardened, the risk, and the fix.
//
// Mount in server.js:
//   import { rtChatRouter } from './rtchat.js';
//   app.use('/v1/redteam', rtChatRouter);
// Full route: POST /v1/redteam/engagements/:id/chat

import { Router } from 'express';
import { pool } from './db.js'; // reuse the app's working Neon pool

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-20b';

// ---- data ---------------------------------------------------------------

async function loadEngagement(id) {
  const { rows } = await pool.query(
    `select id, domain, scope, ownership_verified, review_status
       from engagements where id = $1`, [id]);
  return rows[0] || null;
}

async function loadLatestRun(id) {
  try {
    const { rows } = await pool.query(
      `select id, status, score, blocked, bypassed, signatures, findings, transcript,
              started_at, finished_at
         from autopilot_runs
        where engagement_id = $1
        order by id desc limit 1`, [id]);
    return rows[0] || null;
  } catch { return null; }
}

async function loadSignatures(id) {
  try {
    const { rows } = await pool.query(
      `select pattern, technique from waf_signatures
        where engagement_id = $1 order by id desc limit 30`, [id]);
    return rows;
  } catch { return []; }
}

// ---- context + prompt ---------------------------------------------------

function buildContext(eng, run, sigs) {
  const findings = Array.isArray(run?.findings) ? run.findings
    : (run?.findings ? safeJson(run.findings) : []);
  const ctx = {
    target: eng?.domain || 'unknown',
    status: run?.status || 'no run yet',
    security_score: run?.score ?? null,
    payloads_blocked: run?.blocked ?? 0,
    payloads_bypassed: run?.bypassed ?? 0,
    signatures_learned: run?.signatures ?? sigs.length,
    findings: (findings || []).map(f => ({
      name: f.name, severity: f.severity, endpoint: f.endpoint,
      payload: f.payload, fix: f.fix,
    })),
    hardened_signatures: sigs.map(s => ({ pattern: s.pattern, technique: s.technique })),
  };
  return ctx;
}

function safeJson(v) { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return []; } }

const SYSTEM_PROMPT = `You are the lead red-team operator for Offensive AI. You personally ran an AUTHORIZED, autonomous penetration test against the target below, firing payloads through the customer's own web application firewall (WAF) and recording every verdict.

Your job: answer the user's questions about THIS engagement, in plain language a non-technical executive can follow, while staying precise for an engineer who reads along.

Hard rules:
- Use ONLY the engagement data in the context block. Never invent findings, payloads, numbers, or endpoints.
- If the data does not contain the answer, say so plainly and suggest re-running the engagement.
- If asked about anything outside this engagement (other sites, live production traffic, the SOC dashboard, general trivia), say that is outside the scope of this pentest report.
- When you mention a weakness, always pair it with what is now protecting it (the signature the firewall learned) so the user hears risk AND remediation together.
- Be concise: 2-5 short sentences unless the user asks for detail. No markdown headers.

Explain the core idea whenever useful: when a payload slipped past the firewall (a "bypass"), the system captured it and learned a signature, so the same attack is now blocked for everyone. That is why the security score climbs during the run — the firewall gets stronger as it is attacked.`;

function fallbackAnswer(ctx) {
  if (ctx.status === 'no run yet') {
    return `I haven't run against ${ctx.target} yet. Launch the autopilot and I'll be able to walk you through exactly what I found.`;
  }
  const crit = ctx.findings.filter(f => /crit|high/i.test(f.severity || ''));
  const lead = crit.length
    ? `On ${ctx.target} I found ${ctx.findings.length} weakness${ctx.findings.length === 1 ? '' : 'es'} — the most serious being ${crit[0].name} on ${crit[0].endpoint}.`
    : `On ${ctx.target} the firewall held: I fired ${ctx.payloads_blocked + ctx.payloads_bypassed} payloads and ${ctx.payloads_blocked} were blocked.`;
  const harden = ctx.signatures_learned
    ? ` I captured ${ctx.payloads_bypassed} bypass${ctx.payloads_bypassed === 1 ? '' : 'es'} and turned each into a signature, so those attacks are now blocked automatically. Security score is ${ctx.security_score}.`
    : ` Security score is ${ctx.security_score}.`;
  return lead + harden;
}

// ---- Groq ---------------------------------------------------------------

async function askGroq(messages) {
  const key = process.env.GROQ_API_KEY;
  if (!key) return { ok: false, reason: 'no-groq-key' };
  try {
    const r = await fetch(GROQ_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({ model: GROQ_MODEL, messages, temperature: 0.3, max_tokens: 700 }),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      return { ok: false, reason: `groq-${r.status}`, detail: body.slice(0, 200) };
    }
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content?.trim();
    if (!answer) return { ok: false, reason: 'groq-empty' };
    return { ok: true, answer };
  } catch (e) {
    return { ok: false, reason: 'groq-exception', detail: String(e).slice(0, 200) };
  }
}

// ---- route --------------------------------------------------------------

export const rtChatRouter = Router();

rtChatRouter.post('/engagements/:id/chat', async (req, res) => {
 try {
  const id = req.params.id;
  const question = (req.body?.question || req.body?.message || '').toString().slice(0, 2000);
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-8) : [];
  if (!question) return res.status(400).json({ error: 'question required' });

  const eng = await loadEngagement(id);
  if (!eng) return res.status(404).json({ error: 'engagement not found' });

  const run = await loadLatestRun(id);
  const sigs = await loadSignatures(id);
  const ctx = buildContext(eng, run, sigs);

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'system', content: 'ENGAGEMENT CONTEXT (ground truth, JSON):\n' + JSON.stringify(ctx, null, 2) },
    ...history
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && m.content)
      .map(m => ({ role: m.role, content: String(m.content).slice(0, 2000) })),
    { role: 'user', content: question },
  ];

  const g = await askGroq(messages);
  if (g.ok) return res.json({ answer: g.answer, mode: 'groq', model: GROQ_MODEL });
  return res.json({ answer: fallbackAnswer(ctx), mode: 'fallback', reason: g.reason });
 } catch (e) {
  console.error('[rtchat]', e);
  return res.status(500).json({ error: 'chat failed', detail: String(e).slice(0, 200) });
 }
});

// convenience: read the latest run (used by the report view / chat preload)
rtChatRouter.get('/engagements/:id/autopilot/last', async (req, res) => {
 try {
  const eng = await loadEngagement(req.params.id);
  if (!eng) return res.status(404).json({ error: 'engagement not found' });
  const run = await loadLatestRun(req.params.id);
  const sigs = await loadSignatures(req.params.id);
  res.json({ engagement: { id: eng.id, domain: eng.domain }, run: run || null, signatures: sigs });
 } catch (e) {
  console.error('[rtchat:last]', e);
  res.status(500).json({ error: 'read failed', detail: String(e).slice(0, 200) });
 }
});
