// ---------------------------------------------------------------------------
// SOC Analyst: answers plain-language questions about the live traffic, grounded
// ONLY in the real events/overview from the database. Groq writes the prose; the
// numbers and the chips are computed deterministically so they're never invented.
// Falls back to a composed answer when GROQ_API_KEY isn't set.
// ---------------------------------------------------------------------------
import { overview, listEvents } from './db.js';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
// Override with GROQ_MODEL if Groq retires this one. llama-3.3-70b-versatile is a
// current, strong chat model; llama-3.1-8b-instant is the faster/cheaper option.
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

function buildContext(ov, rows) {
  const k = ov.kpis;
  const topOrigins = (ov.origins || []).slice(0, 5).map((o) => ({
    country: o.name || o.cc || 'Unknown',
    blocked: o.blocked,
    topAttack: o.topAttack,
  }));
  const topVectors = (ov.types || []).slice(0, 5).map((t) => ({ name: t.name, pct: t.pct }));
  const recent = (rows || []).slice(0, 20).map((r) => ({
    time: r.time,
    ip: r.ip,
    country: r.country || r.countryCode,
    type: r.attackType,
    confidence: r.confidence,
    action: r.action,
  }));

  const chips = [];
  if (topOrigins[0]) chips.push({ n: String(topOrigins[0].blocked), label: topOrigins[0].country });
  if (topOrigins[1]) chips.push({ n: String(topOrigins[1].blocked), label: topOrigins[1].country });
  if (topVectors[0]) chips.push({ n: `${topVectors[0].pct}%`, label: topVectors[0].name });

  return {
    windowLabel: '24 hours',
    data: {
      blocked_24h: k.blocked,
      requests_24h: k.requests,
      unique_ips: k.uniqueIps,
      new_ips: k.newIps,
      verdict_mix_pct: ov.verdicts,
      top_origins: topOrigins,
      top_vectors: topVectors,
      recent_events: recent,
    },
    chips,
    source: `based on ${k.requests} events · last 24h`,
    empty: (k.requests || 0) === 0,
  };
}

function fallbackAnswer(ctx) {
  const d = ctx.data;
  if (ctx.empty) return 'No attack traffic has hit your API in the last 24 hours.\n\nThe feed is quiet — nothing to action right now.';
  const o = d.top_origins[0];
  const v = d.top_vectors[0];
  const verdict = `${d.blocked_24h} requests were blocked in the last 24 hours.`;
  const parts = [];
  if (o) parts.push(`The heaviest source is ${o.country} with ${o.blocked} blocked${v ? `, mostly ${v.name}` : ''}.`);
  if (d.verdict_mix_pct && d.verdict_mix_pct.allowed > 0) parts.push(`About ${d.verdict_mix_pct.allowed}% of traffic was allowed through — worth a glance.`);
  else parts.push('Nothing notable got through.');
  return `${verdict}\n\n${parts.join(' ')}`;
}

async function askGroq(question, ctx) {
  if (!GROQ_API_KEY) {
    console.warn('[analyst] GROQ_API_KEY not set — using fallback');
    return { text: fallbackAnswer(ctx), mode: 'fallback', reason: 'no-key' };
  }
  const sys =
    'You are a concise security operations (SOC) analyst for the "Offensive AI" dashboard. ' +
    'Answer the user\'s question using ONLY the DATA provided — never invent numbers, IPs, countries, or events that are not in it. ' +
    'Write 2 to 4 plain sentences: no markdown, no bullet lists, no headings. ' +
    'Put a one-sentence verdict on the first line, then a blank line, then brief supporting detail and, if useful, one recommended action. ' +
    'If the data shows no events, say there is no traffic in this window.';
  const user = `QUESTION: ${question}\n\nDATA (last ${ctx.windowLabel}):\n${JSON.stringify(ctx.data)}`;
  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.35,
        max_tokens: 260,
        messages: [
          { role: 'system', content: sys },
          { role: 'user', content: user },
        ],
      }),
      signal: AbortSignal.timeout(25_000),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      console.error('[analyst] groq error', r.status, body.slice(0, 300));
      return { text: fallbackAnswer(ctx), mode: 'fallback', reason: `groq-${r.status}` };
    }
    const d = await r.json();
    const txt = d?.choices?.[0]?.message?.content?.trim();
    if (!txt) return { text: fallbackAnswer(ctx), mode: 'fallback', reason: 'empty' };
    return { text: txt, mode: 'groq' };
  } catch (e) {
    console.error('[analyst] groq exception', e.message);
    return { text: fallbackAnswer(ctx), mode: 'fallback', reason: e.message };
  }
}

export async function handleAnalyst(req, res) {
  const question = String(req.body?.question || '').slice(0, 500).trim();
  if (!question) return res.status(400).json({ error: 'question is required' });
  const [ov, rows] = await Promise.all([overview(), listEvents({ limit: 40 })]);
  const ctx = buildContext(ov, rows);
  const result = await askGroq(question, ctx);
  res.json({ answer: result.text, stats: ctx.chips, source: ctx.source, mode: result.mode, reason: result.reason });
}
