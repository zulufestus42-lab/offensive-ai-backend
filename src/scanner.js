import { config } from './config.js';

// The classifier abbreviates some labels ("Command Inj"); the dashboard shows full names.
const TYPE_NAMES = {
  'command inj': 'Command Injection',
  'command injection': 'Command Injection',
  'cmd injection': 'Command Injection',
  sqli: 'SQL Injection',
  'sql inj': 'SQL Injection',
  'sql injection': 'SQL Injection',
  xss: 'Cross-site scripting',
  'cross site scripting': 'Cross-site scripting',
  'cross-site scripting': 'Cross-site scripting',
  'path traversal': 'Path Traversal',
  'directory traversal': 'Path Traversal',
  lfi: 'Path Traversal',
  ssrf: 'SSRF',
  benign: 'Benign',
  safe: 'Benign',
  normal: 'Benign',
};

export function normaliseType(raw) {
  if (!raw) return 'Unknown';
  const key = String(raw).trim().toLowerCase();
  return TYPE_NAMES[key] ?? String(raw).trim();
}

export function parseConfidence(raw) {
  const n = typeof raw === 'number' ? raw : parseFloat(String(raw ?? '').replace('%', ''));
  if (!Number.isFinite(n)) return 0;
  return Math.min(100, Math.max(0, n <= 1 && String(raw).indexOf('%') === -1 ? n * 100 : n));
}

export function parseAction(raw, confidence) {
  const a = String(raw ?? '').trim().toUpperCase();
  if (a === 'BLOCK' || a === 'ALLOW' || a === 'REVIEW') return a;
  return confidence >= 70 ? 'BLOCK' : 'ALLOW';
}

/** Short, single-line preview of the payload for the log table. Rendered as text, never HTML. */
export function signatureOf(payload) {
  const s = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > 120 ? `${one.slice(0, 117)}...` : one;
}

const toNumber = (v) => (v === null || v === undefined || v === '' ? NaN : Number(v));

/**
 * Read one result in the format your FastAPI returns, e.g.
 * { "IP", "TIMESTAMP", "PATH", "LATITUDE", "LONGITUDE", "PAYLOAD", "CONFIDENCE", "ACTION" }.
 * Keys are matched without regard to case. Optional extras: "INPUT" (the raw text that
 * was scanned, shown as a short preview) and "SIGNATURE".
 */
export function parseScannerResult(raw = {}) {
  const lower = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k.toLowerCase(), v]));
  const get = (...keys) => keys.map((k) => lower[k]).find((v) => v !== undefined && v !== null);
  const confidence = parseConfidence(get('confidence'));
  const time = get('timestamp', 'time');
  const parsedTime = time && !Number.isNaN(Date.parse(time)) ? new Date(time).toISOString() : null;
  const input = get('input', 'raw', 'body');
  const path = get('path');
  return {
    ip: get('ip') ? String(get('ip')) : null,
    time: parsedTime,
    lat: toNumber(get('latitude', 'lat')),
    lon: toNumber(get('longitude', 'lon', 'lng')),
    attackType: normaliseType(get('payload', 'type', 'attacktype')),
    confidence,
    action: parseAction(get('action'), confidence),
    signature: input !== undefined ? signatureOf(input) : (get('signature') ?? (path ? `POST ${path}` : null)),
  };
}

/**
 * Forward a payload to the classifier and normalise its answer.
 * The original client IP is passed on in X-Forwarded-For, so your API can locate the real
 * caller instead of this server.
 */
export async function classify(payload, clientIp) {
  const res = await fetch(config.scannerUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(clientIp ? { 'X-Forwarded-For': clientIp } : {}) },
    body: JSON.stringify({ payload }),
    signal: AbortSignal.timeout(config.scannerTimeoutMs),
  });
  if (!res.ok) throw new Error(`scanner responded ${res.status}`);
  const raw = await res.json();
  return { raw, ...parseScannerResult(raw) };
}
