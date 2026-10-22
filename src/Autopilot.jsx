import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { API_URL, startAutopilot, askPentest, startBypass } from '../../lib/pentest';
import { openReport } from '../../lib/report.js';

const DEFAULT_PHASES = [
  'Recon & mapping', 'Injection', 'Broken access control', 'Sensitive data exposure',
  'Misconfiguration & components', 'Authentication failures', 'SSRF / open redirect',
];
const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const SEV = { CRITICAL: '#E5484D', HIGH: '#F5A524', MEDIUM: '#C99A00', LOW: '#8C8C8C' };

function palette(dark) {
  return dark
    ? { bg:'#0A0A0A', panel:'#121212', panel2:'#0E0E0E', line:'#202020', line2:'#2E2E2E',
        fg:'#F5F5F5', fg2:'#9E9E9E', mute:'#6A6A6A', ink:'#F5F5F5', inkfg:'#0A0A0A', ok:'#3DD68C', byp:'#FF5A5F' }
    : { bg:'#FFFFFF', panel:'#FAFAFA', panel2:'#F3F3F3', line:'#EAEAEA', line2:'#DADADA',
        fg:'#0A0A0A', fg2:'#565656', mute:'#8C8C8C', ink:'#0A0A0A', inkfg:'#FFFFFF', ok:'#1A9E5F', byp:'#D92D20' };
}

const CSS = `
@keyframes ap-pulse{0%,100%{opacity:1}50%{opacity:.25}}
@keyframes ap-blink{50%{opacity:0}}
@keyframes ap-pop{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.ap-beat{animation:ap-pulse 1.3s ease-in-out infinite}
.ap-caret{display:inline-block;width:8px;height:16px;vertical-align:-3px;animation:ap-blink 1s step-end infinite}
.ap-pop{animation:ap-pop .35s ease both}
.ap-feed::-webkit-scrollbar,.ap-conv::-webkit-scrollbar,.ap-finds::-webkit-scrollbar{width:8px}
.ap-feed::-webkit-scrollbar-thumb,.ap-conv::-webkit-scrollbar-thumb,.ap-finds::-webkit-scrollbar-thumb{background:#555;border-radius:4px}
`;

const CHIPS = ['Did we pass or fail?', 'Is my login safe now?', 'What should we fix first?', 'Show me the exact payload'];

export default function Autopilot({ engagement }) {
  const id = engagement?.id ?? '1';
  const domain = engagement?.domain ?? 'your target';

  const [dark, setDark] = useState(true);
  const c = palette(dark);
  const mono = "'Geist Mono', ui-monospace, monospace";
  const sans = "'Geist', system-ui, sans-serif";

  const [tab, setTab] = useState('run');
  const [launched, setLaunched] = useState(false);
  const [feed, setFeed] = useState([]);
  const [phases, setPhases] = useState(DEFAULT_PHASES.map((n) => ({ name: n, status: 'queued' })));
  const [progress, setProgress] = useState({ overallPct: 0, phase: '' });
  const [score, setScore] = useState({ value: 50, blocked: 0, bypassed: 0, signatures: 0 });
  const [findings, setFindings] = useState([]);
  const [probe, setProbe] = useState(null);     // {name, endpoint, index, total}
  const [spin, setSpin] = useState(0);
  const [runId, setRunId] = useState(null);
  const [bypassOffer, setBypassOffer] = useState(null);
  const [bypassBusy, setBypassBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState('');

  const [chat, setChat] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  const socketRef = useRef(null);
  const startedRef = useRef(false);
  const feedRef = useRef(null);
  const convRef = useRef(null);

  // ---- socket (live run) ----
  useEffect(() => {
    if (!launched) return;
    const socket = io(API_URL, { transports: ['websocket', 'polling'] });
    socketRef.current = socket;
    socket.on('connect', () => {
      socket.emit('autopilot:watch', String(id));
      if (!startedRef.current) {
        startedRef.current = true;
        startAutopilot(id).then((r) => r && setRunId(r.runId)).catch((e) => setErr(e.message || 'launch failed'));
      }
    });
    socket.on('start', (s) => { if (s?.plan?.length) setPhases(s.plan.map((p) => ({ name: p.name, owasp: p.owasp, status: 'queued' }))); });
    socket.on('probe', (p) => setProbe(p));
    socket.on('narration', (l) => setFeed((f) => [...f.slice(-300), l]));
    socket.on('phase', (p) => setPhases((ph) => ph.map((x, i) =>
      i < p.index ? { ...x, status: 'done' }
      : i === p.index ? { ...x, status: p.status === 'done' ? 'done' : 'running', findings: p.findings ?? x.findings }
      : x)));
    socket.on('progress', (p) => setProgress(p));
    socket.on('score', (s) => setScore(s));
    socket.on('finding', (f) => setFindings((xs) => [...xs, f]));
    socket.on('bypass_offer', (b) => { setBypassOffer(b); if (b?.runId) setRunId(b.runId); });
    socket.on('bypass_result', () => { setBypassBusy(false); setBypassOffer(null); });
    socket.on('done', (d) => { setDone(true); setProbe(null); if (d) setScore((s) => ({ ...s, ...d })); setPhases((ph) => ph.map((x) => ({ ...x, status: 'done' }))); });
    return () => { socket.disconnect(); socketRef.current = null; startedRef.current = false; };
  }, [launched, id]);

  // morphing spinner
  useEffect(() => {
    if (!launched || done) return;
    const t = setInterval(() => setSpin((s) => (s + 1) % SPIN.length), 80);
    return () => clearInterval(t);
  }, [launched, done]);

  useEffect(() => { if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight; }, [feed]);
  useEffect(() => { if (convRef.current) convRef.current.scrollTop = convRef.current.scrollHeight; }, [chat]);

  // ---- typewriter reveal for the operator's answers ----
  useEffect(() => {
    const i = chat.findIndex((m) => m.role === 'assistant' && m.streaming);
    if (i === -1) return;
    const m = chat[i];
    if (m.shown.length >= m.content.length) {
      const t = setTimeout(() => setChat((cc) => cc.map((x, idx) => idx === i ? { ...x, streaming: false } : x)), 350);
      return () => clearTimeout(t);
    }
    const stepN = Math.max(2, Math.round(m.content.length / 120));
    const t = setTimeout(() => setChat((cc) => cc.map((x, idx) =>
      idx === i ? { ...x, shown: x.content.slice(0, x.shown.length + stepN) } : x)), 18);
    return () => clearTimeout(t);
  }, [chat]);

  async function send(q) {
    const question = (q ?? input).trim();
    if (!question || sending) return;
    setInput('');
    const history = chat.map((m) => ({ role: m.role, content: m.content }));
    setChat((cc) => [...cc, { role: 'user', content: question }]);
    setSending(true);
    try {
      const r = await askPentest(id, question, history);
      setChat((cc) => [...cc, { role: 'assistant', content: r.answer || '…', shown: '', streaming: true }]);
    } catch {
      setChat((cc) => [...cc, { role: 'assistant', content: "I couldn't reach the engagement report just now — try again.", shown: '', streaming: true }]);
    } finally { setSending(false); }
  }

  async function attemptBypass() {
    if (bypassBusy || !bypassOffer) return;
    setBypassBusy(true);
    try { await startBypass(id, bypassOffer.runId || runId, bypassOffer.blockedPattern); }
    catch (e) { setErr(e.message || 'bypass failed'); setBypassBusy(false); }
  }

  function downloadReport() {
    openReport({ domain, findings, score: score.value, blocked: score.blocked, bypassed: score.bypassed, signatures: score.signatures, feed });
  }

  const ringOffset = (263.9 * (1 - score.value / 100)).toFixed(1);
  const kindColor = (k) => ({ byp: c.byp, ok: c.ok, run: c.fg, req: c.fg2, info: c.fg2 }[k] || c.fg2);

  const shell = { background: c.bg, color: c.fg, fontFamily: sans, minHeight: '100%', WebkitFontSmoothing: 'antialiased', display: 'flex', flexDirection: 'column' };
  const tabBtn = (active) => ({ fontSize: 13, fontWeight: active ? 600 : 400, color: active ? c.inkfg : c.fg2, background: active ? c.ink : 'transparent', padding: '7px 14px', borderRadius: 7, border: 'none', cursor: 'pointer', fontFamily: sans });

  return (
    <div style={shell}>
      <style>{CSS}</style>

      {/* top bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 24px', borderBottom: `1px solid ${c.line}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ fontSize: 15, fontWeight: 700, letterSpacing: '.12em' }}>OFFENSIVE AI</span>
          <div style={{ display: 'flex', gap: 2, background: c.panel2, border: `1px solid ${c.line}`, borderRadius: 10, padding: 3 }}>
            <button onClick={() => setTab('run')} style={tabBtn(tab === 'run')}>Live run</button>
            <button onClick={() => setTab('ask')} style={tabBtn(tab === 'ask')}>Ask the operator</button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {launched && !done && <span style={{ fontFamily: mono, display: 'inline-flex', alignItems: 'center', gap: 7, background: c.byp, color: '#fff', borderRadius: 999, padding: '6px 12px', fontSize: 11, fontWeight: 600 }}><span className="ap-beat" style={{ width: 6, height: 6, borderRadius: 999, background: '#fff' }} />LIVE</span>}
          <button onClick={() => setDark((d) => !d)} aria-label="theme" style={{ height: 32, width: 32, border: `1px solid ${c.line2}`, background: 'transparent', color: c.fg2, borderRadius: 9, cursor: 'pointer' }}>{dark ? '☀' : '☾'}</button>
        </div>
      </div>

      {/* ===================== LIVE RUN — launch ===================== */}
      {tab === 'run' && !launched && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
          <div style={{ width: '100%', maxWidth: 540, border: `1px solid ${c.line}`, background: c.panel, borderRadius: 16, padding: 28 }}>
            <div style={{ fontFamily: mono, fontSize: 11, letterSpacing: '.14em', color: c.mute }}>RED TEAM · AUTOPILOT</div>
            <h2 style={{ margin: '10px 0 6px', fontSize: 25, fontWeight: 700 }}>Autonomous engagement</h2>
            <p style={{ margin: 0, color: c.fg2, fontSize: 14, lineHeight: 1.55 }}>
              The AI operator fires real, non-destructive payloads at <b>{domain}</b> through your firewall across the OWASP phases. When one slips past, it captures the attack and hardens the firewall automatically.
            </p>
            <div style={{ margin: '20px 0', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {['Ownership verified', 'Human-approved', 'In scope', `Target locked: ${domain}`].map((t) => (
                <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13.5 }}>
                  <span style={{ width: 20, height: 20, borderRadius: 999, background: c.ink, color: c.inkfg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, flex: 'none' }}>✓</span>{t}
                </div>
              ))}
            </div>
            {err && <div style={{ color: c.byp, fontFamily: mono, fontSize: 13, marginBottom: 12 }}>⚠ {err}</div>}
            <button onClick={() => { setErr(''); setLaunched(true); }} style={{ width: '100%', height: 48, border: 'none', borderRadius: 12, background: c.ink, color: c.inkfg, fontFamily: sans, fontWeight: 700, fontSize: 15, cursor: 'pointer' }}>Launch engagement</button>
          </div>
        </div>
      )}

      {/* ===================== LIVE RUN — running ===================== */}
      {tab === 'run' && launched && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, padding: 24, gap: 14 }}>
          {/* metrics strip */}
          <div style={{ fontFamily: mono, display: 'flex', gap: 24, flexWrap: 'wrap', fontSize: 12, color: c.fg2 }}>
            <span><span style={{ color: c.mute }}>TARGET </span>{domain}</span>
            <span><span style={{ color: c.mute }}>PROGRESS </span>{done ? 100 : progress.overallPct || 0}%</span>
            <span><span style={{ color: c.mute }}>SCORE </span>{score.value}</span>
            <span><span style={{ color: c.mute }}>FINDINGS </span>{findings.length}</span>
            <span><span style={{ color: c.mute }}>BLOCKED </span>{score.blocked}</span>
            <span><span style={{ color: c.mute }}>HARDENED </span>{score.signatures}</span>
          </div>

          <div style={{ flex: 1, display: 'flex', gap: 16, minHeight: 0 }}>
            {/* operator feed */}
            <section style={{ flex: '999 1 0', minWidth: 0, border: `1px solid ${c.line2}`, background: c.panel2, borderRadius: 14, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', borderBottom: `1px solid ${c.line}` }}>
                <span className="ap-beat" style={{ width: 8, height: 8, borderRadius: 999, background: c.fg }} />
                <span style={{ fontSize: 14, fontWeight: 600 }}>AI Operator</span>
                <span style={{ fontFamily: mono, fontSize: 11, color: c.mute, marginLeft: 'auto' }}>{done ? 'engagement complete' : 'live'}</span>
              </div>

              {/* morphing "thinking" status line */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '16px 18px', borderBottom: `1px solid ${c.line}`, minHeight: 64 }}>
                <span style={{ fontFamily: mono, fontSize: 22, width: 22, textAlign: 'center', color: done ? c.ok : c.fg }}>{done ? '✓' : SPIN[spin]}</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 15, fontWeight: 500 }}>{done ? `Engagement complete — ${findings.length} findings` : (probe ? probe.name : 'Launching…')}</div>
                  <div style={{ fontFamily: mono, fontSize: 11.5, color: c.mute, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{done ? `security score ${score.value} · ${score.signatures} signatures learned` : (probe ? probe.endpoint : 'authorized · human-approved · scope locked')}</div>
                </div>
                {probe && probe.total ? <span style={{ fontFamily: mono, fontSize: 12, color: c.fg2, marginLeft: 'auto', flex: 'none' }}>{probe.index}/{probe.total}</span> : null}
              </div>

              {/* arms-race bypass offer */}
              {bypassOffer && !done && (
                <div className="ap-pop" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 18px', borderBottom: `1px solid ${c.line}`, background: dark ? 'rgba(217,45,32,.08)' : 'rgba(217,45,32,.05)' }}>
                  <span style={{ color: c.byp, fontSize: 16 }}>⚠</span>
                  <div style={{ fontSize: 13, color: c.fg, flex: 1, lineHeight: 1.45 }}>Firewall just hardened against the SQL injection. <b>Attempt to bypass its own new rule?</b></div>
                  <button onClick={attemptBypass} disabled={bypassBusy} style={{ flex: 'none', border: `1px solid ${c.byp}`, background: bypassBusy ? 'transparent' : c.byp, color: bypassBusy ? c.byp : '#fff', borderRadius: 9, padding: '9px 16px', fontFamily: sans, fontWeight: 600, fontSize: 13, cursor: bypassBusy ? 'default' : 'pointer' }}>{bypassBusy ? 'Evolving…' : 'Attempt bypass'}</button>
                </div>
              )}

              <div ref={feedRef} className="ap-feed" style={{ flex: 1, padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 6, fontFamily: mono, fontSize: 12.5, lineHeight: 1.6, overflowY: 'auto' }}>
                {feed.length === 0 && <div style={{ color: c.mute }}>waiting for the operator…</div>}
                {feed.map((l, i) => (
                  <div key={i} style={{ color: kindColor(l.kind) }}>
                    <span style={{ color: c.mute }}>{l.ts}</span>{'  '}
                    <span style={{ display: 'inline-block', width: 14, fontWeight: l.kind === 'byp' ? 700 : 400 }}>{l.glyph}</span>{l.text}
                  </div>
                ))}
                {!done && <div style={{ color: c.fg }}><span style={{ display: 'inline-block', width: 14 }}>▸</span>working<span className="ap-caret" style={{ background: c.fg, marginLeft: 3 }} /></div>}
              </div>
            </section>

            {/* right rail: score + kill chain + findings */}
            <section style={{ flex: '0 0 270px', display: 'flex', flexDirection: 'column', gap: 14, minHeight: 0 }}>
              <div style={{ border: `1px solid ${c.line}`, background: c.panel, borderRadius: 14, padding: 16, display: 'flex', alignItems: 'center', gap: 14, flex: 'none' }}>
                <svg viewBox="0 0 100 100" width="70" height="70" aria-hidden="true">
                  <circle cx="50" cy="50" r="42" fill="none" stroke={c.line2} strokeWidth="8" />
                  <circle cx="50" cy="50" r="42" fill="none" stroke={c.fg} strokeWidth="8" strokeLinecap="round" strokeDasharray="263.9" strokeDashoffset={ringOffset} transform="rotate(-90 50 50)" style={{ transition: 'stroke-dashoffset .5s' }} />
                  <text x="50" y="49" textAnchor="middle" fontFamily={mono} fontSize="23" fontWeight="600" fill={c.fg}>{score.value}</text>
                  <text x="50" y="64" textAnchor="middle" fontFamily={mono} fontSize="7" fill={c.mute}>SCORE</text>
                </svg>
                <div><div style={{ fontSize: 11, color: c.mute }}>posture</div><div style={{ fontSize: 13, color: c.fg2, marginTop: 5, lineHeight: 1.4 }}>climbs as the<br />firewall hardens</div></div>
              </div>

              <div style={{ border: `1px solid ${c.line}`, background: c.panel, borderRadius: 14, padding: 16, flex: 'none' }}>
                <div style={{ fontFamily: mono, fontSize: 10, letterSpacing: '.16em', color: c.mute }}>KILL CHAIN</div>
                <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 9 }}>
                  {phases.map((p) => {
                    const d = p.status === 'done', r = p.status === 'running';
                    return (
                      <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                        <span className={r ? 'ap-beat' : ''} style={{ width: 19, height: 19, borderRadius: 999, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: d ? 10 : 8, ...(d ? { background: c.ink, color: c.inkfg } : r ? { border: `2px solid ${c.fg}`, color: c.fg } : { border: `1.5px solid ${c.line2}`, color: c.mute }) }}>{d ? '✓' : r ? '●' : '○'}</span>
                        <span style={{ fontSize: 12.5, color: r ? c.fg : d ? c.fg2 : c.mute }}>{p.name}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ flex: 1, minHeight: 0, border: `1px solid ${c.line}`, background: c.panel, borderRadius: 14, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                <div style={{ fontFamily: mono, fontSize: 10, letterSpacing: '.16em', color: c.mute, padding: '14px 16px 8px' }}>FINDINGS · {findings.length}</div>
                <div className="ap-finds" style={{ flex: 1, overflowY: 'auto', padding: '0 10px 10px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {findings.length === 0 && <div style={{ color: c.mute, fontSize: 12.5, padding: '6px 6px' }}>none yet…</div>}
                  {[...findings].reverse().map((f, i) => (
                    <div key={i} className="ap-pop" style={{ border: `1px solid ${c.line2}`, borderLeft: `3px solid ${SEV[f.severity] || c.mute}`, borderRadius: 9, padding: '9px 11px', background: c.bg }}>
                      <div style={{ fontSize: 12.5, fontWeight: 600, letterSpacing: '-.01em' }}>{f.name}</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 5 }}>
                        <span style={{ fontFamily: mono, fontSize: 9.5, fontWeight: 600, color: '#fff', background: SEV[f.severity] || c.mute, padding: '1px 6px', borderRadius: 4 }}>{f.severity}</span>
                        <span style={{ fontFamily: mono, fontSize: 10.5, color: c.mute }}>{f.owasp}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </div>

          {/* done action bar */}
          {done && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', borderTop: `1px solid ${c.line}`, paddingTop: 14 }}>
              <span style={{ fontSize: 13, color: c.fg2 }}>Engagement complete — {findings.length} vulnerabilities found &amp; hardened.</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
                <button onClick={downloadReport} style={{ border: 'none', borderRadius: 10, background: c.ink, color: c.inkfg, fontFamily: sans, fontWeight: 600, fontSize: 13.5, padding: '11px 18px', cursor: 'pointer' }}>Download report (PDF)</button>
                <button onClick={() => setTab('ask')} style={{ border: `1px solid ${c.line2}`, borderRadius: 10, background: 'transparent', color: c.fg, fontFamily: sans, fontWeight: 600, fontSize: 13.5, padding: '11px 18px', cursor: 'pointer' }}>Ask the operator</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===================== ASK THE OPERATOR ===================== */}
      {tab === 'ask' && (
        <>
          <div style={{ fontFamily: mono, display: 'flex', gap: 26, flexWrap: 'wrap', padding: '14px 24px', borderBottom: `1px solid ${c.line}`, fontSize: 12, color: c.fg2 }}>
            <span><span style={{ color: c.mute }}>TARGET </span>{domain}</span>
            <span><span style={{ color: c.mute }}>SCORE </span>{score.value}</span>
            <span><span style={{ color: c.mute }}>FINDINGS </span>{findings.length}</span>
            <span><span style={{ color: c.mute }}>BLOCKED </span>{score.blocked}</span>
            <span><span style={{ color: c.mute }}>HARDENED </span>{score.signatures}</span>
            {findings.length > 0 && <button onClick={downloadReport} style={{ marginLeft: 'auto', border: `1px solid ${c.line2}`, background: 'transparent', color: c.fg, borderRadius: 8, padding: '5px 12px', fontSize: 12, cursor: 'pointer', fontFamily: sans }}>Download report</button>}
          </div>

          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <div ref={convRef} className="ap-conv" style={{ width: '100%', maxWidth: 720, flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 18, padding: '28px 20px' }}>
              <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 10, color: c.mute, fontSize: 12.5 }}>
                <span style={{ width: 26, height: 26, borderRadius: 999, background: c.ink, color: c.inkfg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700 }}>AI</span>
                Operator · ran this engagement
              </div>
              {chat.length === 0 && (
                <div style={{ alignSelf: 'flex-start', maxWidth: '88%', fontSize: 15, lineHeight: 1.6, color: c.fg2 }}>
                  Ask me anything about this engagement against <b style={{ color: c.fg }}>{domain}</b> — what I found, what got through the firewall, and what to fix first.
                </div>
              )}
              {chat.map((m, i) => m.role === 'user' ? (
                <div key={i} style={{ alignSelf: 'flex-end', maxWidth: '76%', background: c.ink, color: c.inkfg, borderRadius: '16px 16px 4px 16px', padding: '12px 16px', fontSize: 15, lineHeight: 1.5 }}>{m.content}</div>
              ) : (
                <div key={i} style={{ alignSelf: 'flex-start', maxWidth: '88%', fontSize: 15, lineHeight: 1.6, color: c.fg, whiteSpace: 'pre-wrap' }}>
                  {m.streaming ? m.shown : m.content}
                  {m.streaming && <span className="ap-caret" style={{ background: c.fg, marginLeft: 2 }} />}
                </div>
              ))}
              {sending && <div style={{ alignSelf: 'flex-start', color: c.mute, fontFamily: mono, fontSize: 14 }}>operator is thinking<span className="ap-caret" style={{ background: c.mute, marginLeft: 3 }} /></div>}
            </div>

            <div style={{ width: '100%', maxWidth: 720, padding: '0 20px 24px' }}>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
                {CHIPS.map((q) => (
                  <button key={q} onClick={() => send(q)} disabled={sending} style={{ border: `1px solid ${c.line2}`, background: 'transparent', color: c.fg2, borderRadius: 999, padding: '8px 14px', fontSize: 12.5, cursor: sending ? 'default' : 'pointer', fontFamily: sans }}>{q}</button>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', border: `1px solid ${c.line2}`, background: c.panel, borderRadius: 14, padding: '8px 8px 8px 16px' }}>
                <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && send()} placeholder="Ask the operator anything about this engagement…" style={{ flex: 1, border: 'none', background: 'transparent', color: c.fg, fontFamily: sans, fontSize: 14.5, outline: 'none' }} />
                <button onClick={() => send()} disabled={sending} aria-label="Send" style={{ height: 40, width: 44, border: 'none', borderRadius: 10, background: c.ink, color: c.inkfg, fontSize: 17, cursor: sending ? 'default' : 'pointer', opacity: sending ? 0.6 : 1 }}>→</button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
