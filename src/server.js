import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import { config } from './config.js';
import { pool, listEvents, overview } from './db.js';
import { migrate } from './migrate.js';
import { initGeo, cleanIp } from './geo.js';
import { classify, signatureOf, parseScannerResult } from './scanner.js';
import { attachIo, recordEvent } from './events.js';
import { startSimulator } from './simulate.js';
import { redTeamRouter } from './redteam.js';
import { autopilotRouter, attachAutopilotIo } from './autopilot.js';
import { wafRouter } from './waf.js';
import { handleAnalyst } from './analyst.js';

const app = express();
app.set('trust proxy', config.trustProxy);
app.disable('x-powered-by');
app.use(express.json({ limit: '15mb' })); // room for a base64 authorization PDF on Red Team requests
app.use((_req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' });
  next();
});

const corsOptions = { origin: config.corsOrigins, methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] };

function safeEqual(a, b) {
  if (!a || !b) return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

const bearer = (req) => (req.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
const requireToken = (token) => (req, res, next) =>
  safeEqual(bearer(req), token) ? next() : res.status(401).json({ error: 'unauthorized' });

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// ---- Public scan endpoint: classify, geolocate, store, broadcast ----------------
app.post(
  '/v1/scan',
  cors(),
  rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }),
  async (req, res) => {
    const payload = req.body?.payload;
    if (payload === undefined) return res.status(400).json({ error: 'payload is required' });
    try {
      const ip = cleanIp(req.ip);
      const verdict = await classify(payload, ip);
      // Your API's coordinates describe whoever called it. Use them only if it located
      // the real client (its IP matches); otherwise it located this server, so ignore them.
      const sameCaller = verdict.ip && cleanIp(verdict.ip) === ip;
      const event = await recordEvent({
        ip,
        time: verdict.time,
        lat: sameCaller ? verdict.lat : NaN,
        lon: sameCaller ? verdict.lon : NaN,
        attackType: verdict.attackType,
        signature: signatureOf(payload),
        confidence: verdict.confidence,
        action: verdict.action,
      });
      res.json({ ...verdict.raw, IP: ip, COUNTRY: event.country, EVENT_ID: event.id });
    } catch (err) {
      console.error('[scan]', err.message);
      res.status(502).json({ error: 'scanner unavailable' });
    }
  },
);

// ---- Ingest: let the existing classifier push results it already produced -------
app.post('/v1/events', requireToken(config.ingestToken), async (req, res, next) => {
  try {
    await ingest(req, res);
  } catch (e) {
    next(e);
  }
});

// Accepts your FastAPI's response object exactly as it returns it (one object, or an array).
async function ingest(req, res) {
  const items = Array.isArray(req.body) ? req.body.slice(0, 500) : [req.body ?? {}];
  const out = [];
  for (const item of items) {
    const r = parseScannerResult(item);
    if (!r.ip) return res.status(400).json({ error: 'IP is required', received: Object.keys(item) });
    out.push(
      await recordEvent({
        ip: cleanIp(r.ip),
        time: r.time,
        lat: r.lat,
        lon: r.lon,
        attackType: r.attackType,
        signature: r.signature,
        confidence: r.confidence,
        action: r.action,
      }),
    );
  }
  res.status(201).json(Array.isArray(req.body) ? out : out[0]);
}

// ---- Dashboard read API ----------------------------------------------------------
const api = express.Router();
api.use(cors(corsOptions), requireToken(config.dashboardToken));

api.get('/overview', async (_req, res, next) => {
  try {
    res.json(await overview());
  } catch (e) {
    next(e);
  }
});

api.get('/logs', async (req, res, next) => {
  try {
    res.json(await listEvents({ limit: Number(req.query.limit ?? 50), q: String(req.query.q ?? '').slice(0, 100) }));
  } catch (e) {
    next(e);
  }
});

// Cells that start with = + - @ are prefixed so spreadsheet apps never run them as formulas.
const csvCell = (v) => {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};

api.get('/logs.csv', async (req, res, next) => {
  try {
    const rows = await listEvents({ limit: 10000, q: String(req.query.q ?? '').slice(0, 100) });
    const header = ['time', 'ip', 'country', 'city', 'lat', 'lon', 'attack_type', 'signature', 'confidence', 'action'];
    const lines = rows.map((r) =>
      [new Date(r.time).toISOString(), r.ip, r.country, r.city, r.lat, r.lon, r.attackType, r.signature, r.confidence, r.action]
        .map(csvCell)
        .join(','),
    );
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="offense-ai-logs-${Date.now()}.csv"`);
    res.send([header.join(','), ...lines].join('\n'));
  } catch (e) {
    next(e);
  }
});

// SOC Analyst — plain-language Q&A grounded in the live events (Groq + DB).
api.post('/analyst', (req, res, next) => handleAnalyst(req, res).catch(next));

app.use('/api', api);
app.options('/api/*', cors(corsOptions));

// Red Team: engagements, ownership verification, the scope/approval gate, scans + reports.
app.use('/v1/redteam', cors(), redTeamRouter);
// Red Team Autopilot: the autonomous, gated pentest loop (streams over the socket).
app.use('/v1/redteam', cors(), autopilotRouter);
// Inline reverse-proxy WAF for verified customer origins: /waf/<engagementId>/<path>
app.use('/waf', cors(), wafRouter);

app.use((err, _req, res, _next) => {
  console.error('[api]', err);
  res.status(500).json({ error: 'internal error' });
});

// ---- Live feed ---------------------------------------------------------------------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: config.corsOrigins } });
io.use((socket, next) =>
  safeEqual(socket.handshake.auth?.token, config.dashboardToken) ? next() : next(new Error('unauthorized')),
);
io.on('connection', (socket) => {
  socket.join('dashboard');
  // Let a client follow one engagement's autopilot run.
  socket.on('autopilot:watch', (id) => {
    if (id !== undefined && id !== null) socket.join(`autopilot:${id}`);
  });
});
attachIo(io);
attachAutopilotIo(io);

await migrate();
await initGeo();
server.listen(config.port, () => {
  console.log(`[server] listening on :${config.port}`);
  // Sample-traffic generator is hard-disabled — only real attacks are stored.
  // To re-enable demo traffic later, restore: if (config.demoMode) startSimulator();
  void startSimulator;
});
