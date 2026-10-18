import { insertEvent } from './db.js';
import { resolveGeo } from './geo.js';

let io = null;

export function attachIo(server) {
  io = server;
}

/**
 * Store one scan result and push it to every connected dashboard.
 * `lat`/`lon` come from your scanner when it sends them; otherwise GeoLite2 is tried.
 * `geo` (a full location object) is only used by the demo simulator.
 */
export async function recordEvent({ ip, time, lat, lon, attackType, signature, confidence, action, geo }) {
  const g = geo ?? resolveGeo({ ip, lat, lon });
  const event = await insertEvent({
    time: time ?? null,
    ip,
    countryCode: g.countryCode ?? null,
    countryName: g.countryName ?? null,
    city: g.city ?? null,
    lat: g.lat ?? null,
    lon: g.lon ?? null,
    attackType,
    signature,
    confidence,
    action,
  });
  io?.to('dashboard').emit('scan', event);
  return event;
}
