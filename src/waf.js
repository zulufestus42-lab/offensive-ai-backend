// ---------------------------------------------------------------------------
// Inline reverse-proxy WAF. Any customer who has VERIFIED ownership of their
// domain can route traffic through  /waf/<engagementId>/<path...>  :
//
//   request → classify (ML + learned signatures) → BLOCK (403) or FORWARD to
//   the customer's real origin, returning its response.
//
// Blocked requests are recorded on the live dashboard (via the classifier's
// own telemetry). Signatures the Autopilot learns are enforced here in real
// time, so the WAF genuinely hardens as it is tested. It only ever forwards to
// a domain whose owner proved control of it — never an open proxy.
// ---------------------------------------------------------------------------
import { Router } from 'express';
import { pool } from './db.js';
import { config } from './config.js';
import { getEngagement, host } from './redteam.js';

const SCANNER_URL = config.scannerUrl; // FastAPI /v1/scan — classifies + records on the map

// Build the string we classify from the incoming request.
function requestString(req, pathStr) {
  const parts = [pathStr];
  const qs = req.originalUrl.includes('?') ? req.originalUrl.split('?').slice(1).join('?') : '';
  if (qs) { try { parts.push(decodeURIComponent(qs)); } catch { parts.push(qs); } }
  if (req.body && Object.keys(req.body).length) {
    try { parts.push(typeof req.body === 'string' ? req.body : JSON.stringify(req.body)); } catch { /* ignore */ }
  }
  return parts.join(' ').slice(0, 2000);
}

async function classify(reqString, clientIp, path) {
  if (!SCANNER_URL) return { action: 'ALLOW', attackType: 'Unknown' };
  try {
    const r = await fetch(SCANNER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': clientIp || '', 'X-Original-URI': path || '/' },
      body: JSON.stringify({ payload: reqString }),
      signal: AbortSignal.timeout(10_000),
    });
    const d = await r.json().catch(() => ({}));
    const action = String(d.ACTION || d.action || 'ALLOW').toUpperCase() === 'BLOCK' ? 'BLOCK' : 'ALLOW';
    return { action, attackType: d.PAYLOAD || d.attack_type || 'suspicious input' };
  } catch {
    return { action: 'ALLOW', attackType: 'Unknown' };
  }
}

async function signaturesFor(engId) {
  try {
    const { rows } = await pool.query('SELECT pattern FROM waf_signatures WHERE engagement_id = $1', [engId]);
    return rows.map((r) => String(r.pattern).toLowerCase());
  } catch {
    return [];
  }
}

export const wafRouter = Router();

wafRouter.all('/:id/*', async (req, res) => {
  const e = await getEngagement(req.params.id).catch(() => null);
  if (!e) return res.status(404).type('text/plain').send('Offensive AI WAF — unknown site');
  if (!e.ownership_verified) return res.status(403).type('text/plain').send('Offensive AI WAF — this domain is not verified for protection');

  const domain = host(e.domain);
  const upstreamPath = `/${req.params[0] || ''}`;
  const search = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?').slice(1).join('?')}` : '';
  const clientIp = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || req.ip;

  const reqStr = requestString(req, upstreamPath);
  const [verdict, sigs] = await Promise.all([classify(reqStr, clientIp, upstreamPath), signaturesFor(e.id)]);
  const sigHit = sigs.find((s) => reqStr.toLowerCase().includes(s));

  if (verdict.action === 'BLOCK' || sigHit) {
    res.set('x-offai-waf', 'blocked');
    return res.status(403).type('application/json').send(JSON.stringify({
      error: 'Request blocked by Offensive AI WAF',
      reason: sigHit ? 'matched a known attack signature' : `classified as ${verdict.attackType}`,
      path: upstreamPath,
    }));
  }

  // Clean → forward to the customer's real origin and return its response.
  try {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (['host', 'connection', 'content-length', 'accept-encoding'].includes(k.toLowerCase())) continue;
      headers[k] = v;
    }
    let body;
    if (!['GET', 'HEAD'].includes(req.method) && req.body && Object.keys(req.body).length) {
      body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      if (!headers['content-type']) headers['content-type'] = 'application/json';
    }
    const up = await fetch(`https://${domain}${upstreamPath}${search}`, {
      method: req.method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(15_000),
    });
    const buf = Buffer.from(await up.arrayBuffer());
    res.status(up.status);
    const ct = up.headers.get('content-type');
    if (ct) res.set('content-type', ct);
    res.set('x-offai-waf', 'pass');
    return res.send(buf);
  } catch {
    return res.status(502).type('text/plain').send('Offensive AI WAF — origin unreachable');
  }
});
