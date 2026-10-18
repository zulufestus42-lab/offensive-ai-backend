import { recordEvent } from './events.js';

// Sample traffic for demos. IPs come from the reserved documentation ranges
// (RFC 5737), so they never point at a real host. Signatures are descriptions only.
// Coordinates are city centres (Moscow, Beijing, Ashburn, Amsterdam, São Paulo, Lagos,
// Hanoi, Mumbai, Bucharest); the country is resolved from them like real traffic.
const SOURCES = [
  { lat: 55.75, lon: 37.62, weight: 10 },
  { lat: 39.9, lon: 116.4, weight: 8 },
  { lat: 39.04, lon: -77.49, weight: 6 },
  { lat: 52.37, lon: 4.9, weight: 4 },
  { lat: -23.55, lon: -46.63, weight: 3 },
  { lat: 6.52, lon: 3.38, weight: 2 },
  { lat: 21.03, lon: 105.85, weight: 2 },
  { lat: 19.08, lon: 72.88, weight: 1 },
  { lat: 44.43, lon: 26.1, weight: 1 },
];

const ATTACKS = [
  { attackType: 'Command Injection', signature: 'shell separator in parameter', weight: 34 },
  { attackType: 'SQL Injection', signature: 'tautology in login field', weight: 27 },
  { attackType: 'Cross-site scripting', signature: 'event handler attribute', weight: 18 },
  { attackType: 'Path Traversal', signature: 'parent directory sequence', weight: 11 },
  { attackType: 'SSRF', signature: 'internal address in URL', weight: 6 },
];

const PREFIXES = ['192.0.2.', '198.51.100.', '203.0.113.'];

function weighted(list) {
  const total = list.reduce((s, x) => s + x.weight, 0);
  let r = Math.random() * total;
  for (const x of list) if ((r -= x.weight) < 0) return x;
  return list[0];
}

function fakeIp() {
  return PREFIXES[Math.floor(Math.random() * PREFIXES.length)] + (1 + Math.floor(Math.random() * 254));
}

export function startSimulator() {
  console.log('[demo] generating sample traffic');
  const tick = async () => {
    try {
      const { lat, lon } = weighted(SOURCES);
      if (Math.random() < 0.08) {
        await recordEvent({ ip: fakeIp(), attackType: 'Benign', signature: 'JSON form post', confidence: 5 + Math.random() * 30, action: 'ALLOW', lat, lon });
      } else {
        const a = weighted(ATTACKS);
        const confidence = 70 + Math.random() * 29.9;
        await recordEvent({ ip: fakeIp(), attackType: a.attackType, signature: a.signature, confidence, action: 'BLOCK', lat, lon });
      }
    } catch (err) {
      console.error('[demo]', err.message);
    }
    setTimeout(tick, 1500 + Math.random() * 2500);
  };
  tick();
}
