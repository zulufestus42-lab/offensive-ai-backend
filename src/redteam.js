import { API_URL } from './config.js';
import { supabase } from './supabase.js';

// Red Team endpoints live under /v1/redteam. Customer-facing calls now carry the
// signed-in user's Supabase token so the backend can stamp ownership on create
// and enforce it on read (customer B can't see customer C).
const base = `${API_URL}/v1/redteam`;

async function authHeaders() {
  try {
    if (!supabase) return {};
    const { data } = await supabase.auth.getSession();
    const t = data?.session?.access_token;
    return t ? { Authorization: `Bearer ${t}` } : {};
  } catch { return {}; }
}

async function call(path, opts = {}) {
  const res = await fetch(`${base}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(await authHeaders()), ...(opts.headers || {}) },
    ...opts,
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) {
    const msg = data?.reason || data?.error || `request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const createEngagement = (body) => call('/engagements', { method: 'POST', body: JSON.stringify(body) });
export const getEngagement = (id) => call(`/engagements/${id}`);
export const getMyEngagements = () => call('/engagements/mine');
export const verifyOwnership = (id) => call(`/engagements/${id}/verify`, { method: 'POST' });
export const runScan = (id, target) => call(`/engagements/${id}/scan`, { method: 'POST', body: JSON.stringify({ target }) });
export const getFindings = (id) => call(`/engagements/${id}/findings`);
export const generateReport = (scanId) => call(`/scans/${scanId}/report`, { method: 'POST', body: JSON.stringify({}) });
export const startAutopilot = (id) => call(`/engagements/${id}/autopilot`, { method: 'POST', body: JSON.stringify({}) });

// Map the engagement record to a flow stage.
export function stageOf(e) {
  if (!e) return 'request';
  if (e.review_status === 'rejected') return 'rejected';
  if (!e.ownership_verified) return 'verify';
  if (e.review_status !== 'approved') return 'review';
  return 'scan';
}
