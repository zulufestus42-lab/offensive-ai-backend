import { access, readFile } from 'node:fs/promises';
import maxmind from 'maxmind';
import { geoBounds, geoCentroid, geoContains, geoDistance } from 'd3-geo';
import { config } from './config.js';

// ---- Country outlines: turn lat/long into a country (same data the map draws) -------
const world = JSON.parse(await readFile(new URL('./data/countries.geo.json', import.meta.url), 'utf8'));
const COUNTRIES = world.features.map((f) => ({
  code: f.id, // ISO 3166-1 alpha-3, e.g. ZMB
  name: f.properties.name,
  feature: f,
  bounds: geoBounds(f),
  centroid: geoCentroid(f),
}));

function inBox([[w, s], [e, n]], lon, lat) {
  if (lat < s - 0.5 || lat > n + 0.5) return false;
  return w <= e ? lon >= w - 0.5 && lon <= e + 0.5 : lon >= w - 0.5 || lon <= e + 0.5; // box crossing 180°
}

/** Country containing a point; nearest country (within ~600 km) if it sits just off a coastline. */
export function countryFromCoords(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  const p = [lon, lat];
  const hit = COUNTRIES.find((c) => inBox(c.bounds, lon, lat) && geoContains(c.feature, p));
  if (hit) return { countryCode: hit.code, countryName: hit.name };
  let best = null;
  let bestD = Infinity;
  for (const c of COUNTRIES) {
    const d = geoDistance(c.centroid, p);
    if (d < bestD) {
      bestD = d;
      best = c;
    }
  }
  return best && bestD < 0.1 ? { countryCode: best.code, countryName: best.name } : null;
}

// ---- Optional GeoLite2 lookup, used only when an event arrives without coordinates ---
let reader = null;

export async function initGeo() {
  try {
    await access(config.geoipDb);
    reader = await maxmind.open(config.geoipDb);
    console.log(`[geo] GeoLite2 loaded from ${config.geoipDb}`);
  } catch {
    console.log('[geo] no GeoLite2 database; using the coordinates your scanner sends');
  }
}

function lookupIp(ip) {
  if (!reader || !ip || !maxmind.validate(ip)) return null;
  const r = reader.get(ip);
  if (!r?.location) return null;
  return { lat: r.location.latitude, lon: r.location.longitude, city: r.city?.names?.en ?? null };
}

/**
 * Work out where an event came from. Coordinates sent by the scanner win; otherwise the IP
 * is looked up in GeoLite2. The country always comes from the map's own outlines, so the
 * country on a log row is exactly the country shaded on the map.
 */
const hasCoords = (lat, lon) => Number.isFinite(lat) && Number.isFinite(lon) && !(lat === 0 && lon === 0);

export function resolveGeo({ ip, lat, lon }) {
  // (0, 0) is what upstream sends when its own geo lookup failed — treat it as "no location".
  const point = hasCoords(lat, lon) ? { lat, lon, city: null } : lookupIp(ip);
  if (!point) return {};
  return { ...point, ...(countryFromCoords(point.lat, point.lon) ?? {}) };
}

/** Normalise the address Express gives us (strips the IPv4-mapped IPv6 prefix). */
export function cleanIp(ip) {
  if (!ip) return null;
  const s = String(ip).trim();
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}
