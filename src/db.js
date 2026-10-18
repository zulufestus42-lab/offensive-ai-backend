import pg from 'pg';
import { config } from './config.js';

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  max: 10,
  ssl: /sslmode=require|render\.com|neon\.tech|supabase/.test(config.databaseUrl) ? { rejectUnauthorized: false } : undefined,
});

const EVENT_COLUMNS = `id, created_at, host(ip) AS ip, country_code, country_name, city, lat, lon,
  attack_type, signature, confidence::float AS confidence, action`;

export async function insertEvent(e) {
  const { rows } = await pool.query(
    `INSERT INTO scan_events (created_at, ip, country_code, country_name, city, lat, lon, attack_type, signature, confidence, action)
     VALUES (coalesce($1::timestamptz, now()),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     RETURNING ${EVENT_COLUMNS}`,
    [e.time, e.ip, e.countryCode, e.countryName, e.city, e.lat, e.lon, e.attackType, e.signature, e.confidence, e.action],
  );
  return toPublic(rows[0]);
}

function searchClause(q, params) {
  if (!q) return '';
  params.push(`%${q}%`);
  const i = params.length;
  return `AND (host(ip) ILIKE $${i} OR country_name ILIKE $${i} OR attack_type ILIKE $${i} OR signature ILIKE $${i})`;
}

export async function listEvents({ limit = 50, q = '' } = {}) {
  const params = [];
  const where = searchClause(q, params);
  params.push(Math.min(Math.max(limit, 1), 10000));
  const { rows } = await pool.query(
    `SELECT ${EVENT_COLUMNS} FROM scan_events WHERE true ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
    params,
  );
  return rows.map(toPublic);
}

export async function overview() {
  const [totals, hourly, types, verdicts, origins] = await Promise.all([
    pool.query(`
      SELECT
        count(*) FILTER (WHERE created_at > now() - interval '24 hours')::int AS requests,
        count(*) FILTER (WHERE created_at BETWEEN now() - interval '48 hours' AND now() - interval '24 hours')::int AS requests_prev,
        count(*) FILTER (WHERE action = 'BLOCK' AND created_at > now() - interval '24 hours')::int AS blocked,
        count(DISTINCT ip) FILTER (WHERE created_at > now() - interval '24 hours')::int AS unique_ips,
        (SELECT count(DISTINCT s.ip)::int FROM scan_events s
          WHERE s.created_at > now() - interval '24 hours'
            AND NOT EXISTS (SELECT 1 FROM scan_events o WHERE o.ip = s.ip AND o.created_at <= now() - interval '24 hours')) AS new_ips,
        percentile_cont(0.5) WITHIN GROUP (ORDER BY confidence)
          FILTER (WHERE action = 'BLOCK' AND created_at > now() - interval '24 hours') AS median_confidence
      FROM scan_events
      WHERE created_at > now() - interval '48 hours'`),
    pool.query(`
      SELECT h.hour, coalesce(count(e.id), 0)::int AS blocked
      FROM generate_series(date_trunc('hour', now()) - interval '23 hours', date_trunc('hour', now()), interval '1 hour') AS h(hour)
      LEFT JOIN scan_events e
        ON e.action = 'BLOCK' AND date_trunc('hour', e.created_at) = h.hour
      GROUP BY h.hour ORDER BY h.hour`),
    pool.query(`
      SELECT attack_type, count(*)::int AS n FROM scan_events
      WHERE action = 'BLOCK' AND created_at > now() - interval '24 hours'
      GROUP BY attack_type ORDER BY n DESC LIMIT 5`),
    pool.query(`
      SELECT
        count(*) FILTER (WHERE confidence >= 70)::int AS blocked,
        count(*) FILTER (WHERE confidence >= 40 AND confidence < 70)::int AS review,
        count(*) FILTER (WHERE confidence < 40)::int AS allowed
      FROM scan_events WHERE created_at > now() - interval '24 hours'`),
    pool.query(`
      SELECT country_code, max(country_name) AS country_name,
        avg(lat) AS lat, avg(lon) AS lon,
        count(*)::int AS blocked, count(DISTINCT ip)::int AS unique_ips,
        mode() WITHIN GROUP (ORDER BY attack_type) AS top_attack,
        max(created_at) AS last_seen
      FROM scan_events
      WHERE action = 'BLOCK' AND lat IS NOT NULL AND created_at > now() - interval '24 hours'
      GROUP BY country_code ORDER BY blocked DESC LIMIT 9`),
  ]);

  const t = totals.rows[0];
  const typeTotal = types.rows.reduce((s, r) => s + r.n, 0) || 1;
  const v = verdicts.rows[0];
  const vTotal = v.blocked + v.review + v.allowed || 1;

  return {
    kpis: {
      requests: t.requests,
      requestsPrev: t.requests_prev,
      blocked: t.blocked,
      uniqueIps: t.unique_ips,
      newIps: t.new_ips,
      medianConfidence: t.median_confidence === null ? null : Number(t.median_confidence),
    },
    hourly: hourly.rows.map((r) => ({ hour: r.hour, blocked: r.blocked })),
    types: types.rows.map((r) => ({ name: r.attack_type, pct: Math.round((r.n / typeTotal) * 100) })),
    verdicts: {
      blocked: Math.round((v.blocked / vTotal) * 100),
      review: Math.round((v.review / vTotal) * 100),
      allowed: Math.round((v.allowed / vTotal) * 100),
    },
    origins: origins.rows.map((r) => ({
      cc: r.country_code,
      name: r.country_name,
      lat: Number(r.lat),
      lon: Number(r.lon),
      blocked: r.blocked,
      uniqueIps: r.unique_ips,
      topAttack: r.top_attack,
      lastSeen: r.last_seen,
    })),
  };
}

function toPublic(r) {
  return {
    id: String(r.id),
    time: r.created_at,
    ip: r.ip,
    countryCode: r.country_code,
    country: r.country_name,
    city: r.city,
    lat: r.lat,
    lon: r.lon,
    attackType: r.attack_type,
    signature: r.signature,
    confidence: r.confidence,
    action: r.action,
  };
}
