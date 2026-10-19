// ---------------------------------------------------------------------------
// SOC Analyst: answers plain-language questions about the live traffic, grounded
// ONLY in the real events/overview from the database. Groq writes the prose; the
// numbers and the chips are computed deterministically so they're never invented.
// Falls back to a composed answer when GROQ_API_KEY isn't set.
// ---------------------------------------------------------------------------
import { overview, listEvents } from './db.js';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
// Override with GROQ_MODEL if Groq retires this one. This is the same model the
// FastAPI scanner uses; llama-3.3-70b-versatile gives richer answers if available.
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';

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

const SYSTEM_PROMPT = [
  'You are "Analyst", a calm, friendly security assistant built into the Offensive AI dashboard.',
  'You are talking to a business owner or executive who is NOT technical — assume they do not know security jargon.',
  '',
  'How to answer:',
  '- Answer ANY question they ask, naturally and conversationally, like a knowledgeable friend. Greetings, vague questions ("are we okay?", "should I be worried?"), and specific ones all get a real reply.',
  '- Use plain English. Avoid jargon; if you must use a term (like "payload" or "injection"), explain it in a few plain words. Never make them feel they should already know something.',
  '- Base every FACT (numbers, countries, attack types, what got through) ONLY on the DATA block provided. Never invent figures, IPs, or events. The DATA covers the last 24 hours of traffic to their system.',
  '- If the question is not answerable from the DATA, say what you can see and offer that, instead of refusing.',
  '- Keep it short and human: usually 2 to 5 sentences. No markdown, no bullet points, no headings, no numbered lists. Reassure when things are fine; be clear and direct when they are not.',
  '- You remember the earlier conversation and can answer follow-ups naturally.',
].join('\n');

function dataBlock(ctx) {
  return `Here is the live DATA for the last ${ctx.windowLabel} — use it for all facts:\n${JSON.stringify(ctx.data)}`;
}

async function askGroq(question, ctx, history) {
  if (!GROQ_API_KEY) {
    console.warn('[analyst] GROQ_API_KEY not set — using fallback');
    return { text: fallbackAnswer(ctx), mode: 'fallback', reason: 'no-key' };
  }
  const messages = [{ role: 'system', content: SYSTEM_PROMPT }];
  for (const h of history) {
    const role = h.role === 'assistant' ? 'assistant' : 'user';
    const content = String(h.content ?? h.text ?? '').slice(0, 1200);
    if (content) messages.push({ role, content });
  }
  // Attach the fresh data to the current question so facts are always current.
  messages.push({ role: 'user', content: `${question}\n\n${dataBlock(ctx)}` });

  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: GROQ_MODEL, temperature: 0.45, max_tokens: 320, messages }),
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
  const question = String(req.body?.question || '').slice(0, 800).trim();
  if (!question) return res.status(400).json({ error: 'question is required' });
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-8) : [];
  const [ov, rows] = await Promise.all([overview(), listEvents({ limit: 40 })]);
  const ctx = buildContext(ov, rows);
  const result = await askGroq(question, ctx, history);
  // Stats only accompany the first answer of a conversation, so the chat stays clean.
  const withStats = history.length === 0;
  res.json({
    answer: result.text,
    stats: withStats ? ctx.chips : [],
    source: withStats ? ctx.source : null,
    mode: result.mode,
    reason: result.reason,
  });
}
