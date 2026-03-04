import { useState, useEffect, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

// ── API base URL ───────────────────────────────────────────────────
// In dev: uses VITE_API_URL from .env.local (defaults to localhost:8000)
// In production (Render): VITE_API_URL is set to the live backend URL
const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── Global Styles ─────────────────────────────────────────────────
const GlobalStyles = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;600;800&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #060810;
      --surface:  #0d1117;
      --panel:    #111827;
      --border:   #1e2d45;
      --accent:   #00d4ff;
      --accent2:  #ff3c6e;
      --accent3:  #00ff9f;
      --text:     #c9d1d9;
      --muted:    #4a5568;
      --critical: #ff3c6e;
      --high:     #ff8c42;
      --medium:   #ffd700;
      --low:      #00ff9f;
      --font-mono: 'Share Tech Mono', monospace;
      --font-ui:   'Exo 2', sans-serif;
      --font-head: 'Rajdhani', sans-serif;
    }

    html, body, #root {
      height: 100%; background: var(--bg);
      color: var(--text); font-family: var(--font-ui);
      overflow-x: hidden;
    }

    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 9999; pointer-events: none;
      background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px
      );
    }

    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: var(--surface); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    @keyframes pulse-glow {
      0%, 100% { box-shadow: 0 0 8px rgba(0,212,255,0.3); }
      50%       { box-shadow: 0 0 20px rgba(0,212,255,0.7); }
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
    @keyframes slide-in {
      from { opacity:0; transform: translateY(16px); }
      to   { opacity:1; transform: translateY(0); }
    }
  `}</style>
);

// ── Helpers ────────────────────────────────────────────────────────
const sev = (s) => ({ Critical:"--critical", High:"--high", Medium:"--medium", Low:"--low" }[s] || "--muted");
const formatTime = (iso) => iso ? new Date(iso).toLocaleTimeString() : "—";
const formatDate = (iso) => iso ? new Date(iso).toLocaleString() : "—";

// ── TopBar ─────────────────────────────────────────────────────────
function TopBar({ live, lastUpdate, onRefresh, loading }) {
  const [tick, setTick] = useState(true);
  useEffect(() => {
    const t = setInterval(() => setTick(p => !p), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header style={{
      background: "linear-gradient(90deg, #0d1117 0%, #111827 50%, #0d1117 100%)",
      borderBottom: "1px solid var(--border)",
      padding: "0 24px", height: 56,
      display: "flex", alignItems: "center", justifyContent: "space-between",
      position: "sticky", top: 0, zIndex: 100,
      boxShadow: "0 2px 20px rgba(0,212,255,0.1)"
    }}>
      <div style={{ display:"flex", alignItems:"center", gap:16 }}>
        <svg width="28" height="28" viewBox="0 0 28 28">
          <polygon points="14,2 26,8 26,20 14,26 2,20 2,8" fill="none" stroke="var(--accent)" strokeWidth="1.5"/>
          <polygon points="14,7 21,11 21,18 14,22 7,18 7,11" fill="rgba(0,212,255,0.1)" stroke="var(--accent)" strokeWidth="1"/>
          <circle cx="14" cy="14" r="3" fill="var(--accent)"/>
        </svg>
        <div>
          <div style={{ fontFamily:"var(--font-head)", fontSize:18, fontWeight:700, letterSpacing:2, color:"#fff" }}>
            STIX<span style={{color:"var(--accent)"}}>.</span>INTEL
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--muted)", letterSpacing:1 }}>
            THREAT CORRELATION PLATFORM v2.1
          </div>
        </div>
      </div>

      <div style={{ display:"flex", alignItems:"center", gap:24 }}>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)" }}>
          LAST SYNC: <span style={{color:"var(--accent3)"}}>{lastUpdate ? formatTime(lastUpdate) : "—"}</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <div style={{
            width:8, height:8, borderRadius:"50%",
            background: live ? "var(--accent3)" : "var(--critical)",
            boxShadow: live ? "0 0 8px var(--accent3)" : "none",
            animation: live ? "pulse-glow 2s infinite" : "none"
          }}/>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color: live ? "var(--accent3)" : "var(--critical)" }}>
            {live ? "LIVE" : "OFFLINE"}
          </span>
        </div>
        <button onClick={onRefresh} disabled={loading} style={{
          background: "transparent", border: "1px solid var(--border)",
          color: loading ? "var(--muted)" : "var(--accent)", cursor: loading ? "wait" : "pointer",
          padding: "6px 14px", fontFamily:"var(--font-mono)", fontSize:11, letterSpacing:1,
          transition: "all 0.2s", borderRadius: 2,
        }}>
          {loading ? "SYNCING..." : "↺ REFRESH"}
        </button>
      </div>
    </header>
  );
}

// ── StatCard ───────────────────────────────────────────────────────
function StatCard({ label, value, sub, color, icon, delay=0 }) {
  return (
    <div style={{
      background: "var(--panel)",
      border: `1px solid ${color || "var(--border)"}`,
      borderRadius: 4, padding: "20px 24px",
      position: "relative", overflow: "hidden",
      animation: `slide-in 0.4s ease ${delay}s both`,
      boxShadow: color ? `0 0 20px ${color}22` : "none",
    }}>
      <div style={{
        position:"absolute", top:0, right:0, width:40, height:40,
        background: `linear-gradient(225deg, ${color || "var(--border)"} 0%, transparent 70%)`,
        opacity:0.4
      }}/>
      <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", letterSpacing:2, marginBottom:10 }}>
        {icon} {label}
      </div>
      <div style={{
        fontFamily:"var(--font-head)", fontSize:44, fontWeight:800,
        color: color || "var(--text)", lineHeight:1, letterSpacing:-1
      }}>
        {value?.toLocaleString() ?? "—"}
      </div>
      {sub && <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", marginTop:8 }}>{sub}</div>}
    </div>
  );
}

// ── Panel ──────────────────────────────────────────────────────────
function Panel({ title, children, style={} }) {
  return (
    <div style={{
      background: "var(--panel)", border: "1px solid var(--border)",
      borderRadius: 4, overflow:"hidden", ...style
    }}>
      <div style={{
        padding: "12px 20px", borderBottom: "1px solid var(--border)",
        display:"flex", alignItems:"center", gap:8,
        background:"rgba(0,212,255,0.03)"
      }}>
        <div style={{ width:2, height:14, background:"var(--accent)" }}/>
        <span style={{ fontFamily:"var(--font-head)", fontSize:13, fontWeight:600, letterSpacing:2, color:"var(--accent)" }}>
          {title}
        </span>
      </div>
      <div style={{ padding:20 }}>{children}</div>
    </div>
  );
}

// ── Charts ─────────────────────────────────────────────────────────
const SEV_COLORS = { Critical:"#ff3c6e", High:"#ff8c42", Medium:"#ffd700", Low:"#00ff9f" };

function SeverityChart({ data }) {
  const chartData = Object.entries(data || {}).map(([name, value]) => ({ name, value }));
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} barSize={32}>
        <XAxis dataKey="name" tick={{ fontFamily:"var(--font-mono)", fontSize:10, fill:"var(--muted)" }} axisLine={false} tickLine={false}/>
        <YAxis tick={{ fontFamily:"var(--font-mono)", fontSize:10, fill:"var(--muted)" }} axisLine={false} tickLine={false}/>
        <Tooltip contentStyle={{ background:"var(--surface)", border:"1px solid var(--border)", fontFamily:"var(--font-mono)", fontSize:11 }} cursor={{ fill:"rgba(255,255,255,0.03)" }}/>
        <Bar dataKey="value" radius={[2,2,0,0]}>
          {chartData.map((entry) => <Cell key={entry.name} fill={SEV_COLORS[entry.name] || "#4a5568"}/>)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── ThreatRow ──────────────────────────────────────────────────────
function ThreatRow({ threat, index }) {
  return (
    <div style={{
      display:"grid", gridTemplateColumns:"1fr auto",
      padding:"10px 0", borderBottom:"1px solid var(--border)",
      animation:`slide-in 0.3s ease ${index*0.05}s both`
    }}>
      <div>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--accent)", marginBottom:2 }}>
          {threat.matched_ip}
        </div>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
          {threat.decision} · {formatDate(threat.detected_at)}
        </div>
      </div>
      <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:4 }}>
        <span style={{
          fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
          color:`var(${sev(threat.severity)})`,
          border:`1px solid var(${sev(threat.severity)})`,
          padding:"2px 8px", borderRadius:2,
          textShadow:`0 0 8px var(${sev(threat.severity)})`
        }}>
          {threat.severity || "—"}
        </span>
        <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
          {threat.risk_score ? `${threat.risk_score}/100` : ""}
        </span>
      </div>
    </div>
  );
}

// ── IOCTable ───────────────────────────────────────────────────────
function IOCTable({ iocs }) {
  return (
    <div style={{ overflowX:"auto" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontFamily:"var(--font-mono)", fontSize:11 }}>
        <thead>
          <tr style={{ borderBottom:"1px solid var(--border)" }}>
            {["TYPE","VALUE","CONFIDENCE","SOURCE","ADDED"].map(h => (
              <th key={h} style={{ padding:"8px 12px", textAlign:"left", color:"var(--muted)", letterSpacing:1, fontWeight:400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={ioc.id || i}
              style={{ borderBottom:"1px solid rgba(30,45,69,0.5)", animation:`slide-in 0.3s ease ${i*0.03}s both`, transition:"background 0.15s" }}
              onMouseEnter={e => e.currentTarget.style.background="rgba(0,212,255,0.04)"}
              onMouseLeave={e => e.currentTarget.style.background="transparent"}
            >
              <td style={{ padding:"9px 12px" }}>
                <span style={{ background:"rgba(0,212,255,0.1)", color:"var(--accent)", padding:"2px 8px", borderRadius:2, fontSize:10, letterSpacing:1 }}>
                  {(ioc.ioc_type || "?").toUpperCase()}
                </span>
              </td>
              <td style={{ padding:"9px 12px", color:"#e6edf3", maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                {ioc.ioc_value}
              </td>
              <td style={{ padding:"9px 12px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <div style={{ flex:1, height:3, background:"var(--border)", borderRadius:2, maxWidth:60 }}>
                    <div style={{ width:`${ioc.confidence || 0}%`, height:"100%", background:"var(--accent)", borderRadius:2 }}/>
                  </div>
                  <span style={{ color:"var(--muted)" }}>{ioc.confidence ?? "—"}</span>
                </div>
              </td>
              <td style={{ padding:"9px 12px", color:"var(--muted)" }}>{ioc.source}</td>
              <td style={{ padding:"9px 12px", color:"var(--muted)" }}>{ioc.created_at ? new Date(ioc.created_at).toLocaleDateString() : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── EventForm ──────────────────────────────────────────────────────
function EventForm({ onResult }) {
  const [form, setForm] = useState({
    event_id: `evt-${Date.now().toString().slice(-4)}`,
    source_ip: "", destination_ip: "",
    source_port: "", destination_port: "", protocol: "TCP"
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    if (!form.source_ip || !form.destination_ip) { setError("Source and Destination IP required"); return; }
    setLoading(true); setError("");
    try {
      const res = await fetch(`${API}/event`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          ...form,
          source_port: form.source_port ? parseInt(form.source_port) : null,
          destination_port: form.destination_port ? parseInt(form.destination_port) : null,
        })
      });
      const data = await res.json();
      onResult(data);
      setForm(f => ({ ...f, event_id:`evt-${Date.now().toString().slice(-4)}`, source_ip:"", destination_ip:"" }));
    } catch {
      setError("API connection failed. Is the server running?");
    } finally { setLoading(false); }
  };

  const inp = (key, placeholder, type="text") => (
    <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
      <label style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", letterSpacing:1 }}>
        {key.replace(/_/g," ").toUpperCase()}
      </label>
      <input
        type={type} placeholder={placeholder} value={form[key]}
        onChange={e => setForm(f => ({...f, [key]: e.target.value}))}
        style={{
          background:"var(--surface)", border:"1px solid var(--border)",
          color:"var(--text)", padding:"8px 12px", borderRadius:2,
          fontFamily:"var(--font-mono)", fontSize:12, outline:"none",
          transition:"border-color 0.2s"
        }}
        onFocus={e => e.target.style.borderColor="var(--accent)"}
        onBlur={e => e.target.style.borderColor="var(--border)"}
      />
    </div>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
        {inp("event_id","evt-001")}
        {inp("protocol","TCP")}
        {inp("source_ip","192.168.1.10")}
        {inp("destination_ip","185.81.113.73")}
        {inp("source_port","54231","number")}
        {inp("destination_port","443","number")}
      </div>
      {error && <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--critical)", padding:"8px 12px", border:"1px solid var(--critical)", borderRadius:2 }}>{error}</div>}
      <button onClick={submit} disabled={loading} style={{
        background: loading ? "var(--surface)" : "linear-gradient(90deg, rgba(0,212,255,0.15), rgba(0,212,255,0.05))",
        border:"1px solid var(--accent)", color:"var(--accent)",
        padding:"12px", borderRadius:2, cursor: loading ? "wait" : "pointer",
        fontFamily:"var(--font-head)", fontSize:14, fontWeight:600, letterSpacing:3,
        transition:"all 0.2s",
        boxShadow: loading ? "none" : "0 0 15px rgba(0,212,255,0.15)"
      }}>
        {loading ? "⟳  CORRELATING..." : "▶  SUBMIT EVENT"}
      </button>
    </div>
  );
}

// ── ResultAlert ────────────────────────────────────────────────────
function ResultAlert({ result, onClose }) {
  if (!result) return null;
  const threat = result.status === "threat_detected";
  return (
    <div style={{
      border:`1px solid ${threat ? "var(--critical)" : "var(--accent3)"}`,
      background: threat ? "rgba(255,60,110,0.08)" : "rgba(0,255,159,0.08)",
      borderRadius:4, padding:16, position:"relative",
      animation:"slide-in 0.3s ease",
      boxShadow: threat ? "0 0 20px rgba(255,60,110,0.2)" : "0 0 20px rgba(0,255,159,0.2)"
    }}>
      <button onClick={onClose} style={{ position:"absolute", top:10, right:12, background:"none", border:"none", color:"var(--muted)", cursor:"pointer", fontSize:16 }}>✕</button>
      <div style={{ fontFamily:"var(--font-head)", fontSize:16, fontWeight:700, letterSpacing:2, color: threat ? "var(--critical)" : "var(--accent3)", marginBottom:8 }}>
        {threat ? "⚠  THREAT DETECTED" : "✓  BENIGN ACTIVITY"}
      </div>
      <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", marginBottom: result.results?.length ? 12 : 0 }}>
        Event: {result.event_id} · {result.threats_found} match(es)
        {result.top_severity && <> · Severity: <span style={{color:`var(${sev(result.top_severity)})`}}>{result.top_severity}</span></>}
      </div>
      {result.results?.map((r,i) => (
        <div key={i} style={{ fontFamily:"var(--font-mono)", fontSize:11, padding:"6px 0", borderTop:"1px solid rgba(255,255,255,0.05)" }}>
          <span style={{color:"var(--accent)"}}>{r.matched_ip}</span> · {r.decision} · Score: <span style={{color:`var(${sev(r.severity)})`}}>{r.risk_score}/100</span>
          {r.mitre_tactic && <> · MITRE: {r.mitre_tactic}</>}
        </div>
      ))}
    </div>
  );
}

// ── TopThreats ─────────────────────────────────────────────────────
function TopThreats({ threats }) {
  const max = Math.max(...threats.map(t => t.hit_count || 1), 1);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
      {threats.length === 0 && <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:20 }}>No threat data yet</div>}
      {threats.map((t, i) => (
        <div key={i} style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--accent)", width:130, flexShrink:0 }}>{t.matched_ip}</div>
          <div style={{ flex:1, height:4, background:"var(--border)", borderRadius:2 }}>
            <div style={{ width:`${((t.hit_count||1)/max)*100}%`, height:"100%", background:`linear-gradient(90deg, var(--critical), var(--high))`, borderRadius:2, transition:"width 0.6s ease" }}/>
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", width:24, textAlign:"right" }}>{t.hit_count}</div>
        </div>
      ))}
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────
export default function App() {
  const [metrics, setMetrics]         = useState(null);
  const [correlations, setCorr]       = useState([]);
  const [iocs, setIocs]               = useState([]);
  const [iocPage, setIocPage]         = useState(0);
  const [iocSearch, setIocSearch]     = useState("");
  const [iocType, setIocType]         = useState("");
  const [loading, setLoading]         = useState(false);
  const [live, setLive]               = useState(false);
  const [lastUpdate, setLastUpdate]   = useState(null);
  const [tab, setTab]                 = useState("overview");
  const [eventResult, setEventResult] = useState(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [mRes, cRes, iRes] = await Promise.all([
        fetch(`${API}/metrics`),
        fetch(`${API}/correlations?limit=20`),
        fetch(`${API}/iocs?limit=50&offset=${iocPage * 50}${iocType ? `&ioc_type=${iocType}` : ""}`)
      ]);
      if (mRes.ok) { setMetrics(await mRes.json()); setLive(true); }
      if (cRes.ok) { const d = await cRes.json(); setCorr(d.results || []); }
      if (iRes.ok) { const d = await iRes.json(); setIocs(d.iocs || []); }
      setLastUpdate(new Date().toISOString());
    } catch { setLive(false); }
    finally { setLoading(false); }
  }, [iocPage, iocType]);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  useEffect(() => { const t = setInterval(fetchAll, 30000); return () => clearInterval(t); }, [fetchAll]);

  const stats = metrics?.statistics || {};
  const severityData = {
    Critical: stats.severity_breakdown?.critical || 0,
    High:     stats.severity_breakdown?.high     || 0,
    Medium:   correlations.filter(c => c.severity === "Medium").length,
    Low:      correlations.filter(c => c.severity === "Low").length,
  };

  const filteredIocs = iocSearch
    ? iocs.filter(i => i.ioc_value?.toLowerCase().includes(iocSearch.toLowerCase()))
    : iocs;

  const navItem = (id, label) => (
    <button onClick={() => setTab(id)} style={{
      background: "none", border: "none", cursor: "pointer",
      fontFamily:"var(--font-head)", fontSize:13, fontWeight:600, letterSpacing:2,
      color: tab === id ? "var(--accent)" : "var(--muted)",
      padding:"18px 16px",
      borderBottom: tab === id ? "2px solid var(--accent)" : "2px solid transparent",
      transition:"all 0.2s"
    }}>{label}</button>
  );

  return (
    <>
      <GlobalStyles/>
      <div style={{ minHeight:"100vh", display:"flex", flexDirection:"column" }}>
        <TopBar live={live} lastUpdate={lastUpdate} onRefresh={fetchAll} loading={loading}/>

        <div style={{ background:"var(--surface)", borderBottom:"1px solid var(--border)", padding:"0 24px", display:"flex", gap:4 }}>
          {navItem("overview","OVERVIEW")}
          {navItem("correlations","DETECTIONS")}
          {navItem("iocs","IOC DATABASE")}
          {navItem("submit","SUBMIT EVENT")}
        </div>

        <main style={{ flex:1, padding:24, maxWidth:1400, width:"100%", margin:"0 auto" }}>

          {/* OVERVIEW */}
          {tab === "overview" && (
            <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(200px,1fr))", gap:16 }}>
                <StatCard label="TOTAL IOCs"      value={stats.total_iocs}                        sub="Threat indicators stored"   color="var(--accent)"   icon="◈" delay={0}/>
                <StatCard label="EVENTS LOGGED"   value={stats.total_events}                      sub="Network events analyzed"    color="var(--accent3)"  icon="◉" delay={0.05}/>
                <StatCard label="CORRELATIONS"    value={stats.total_correlations}                sub="IOC matches detected"       color="var(--high)"     icon="◎" delay={0.1}/>
                <StatCard label="CRITICAL ALERTS" value={stats.severity_breakdown?.critical ?? 0} sub="Immediate action required"  color="var(--critical)" icon="⬡" delay={0.15}/>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
                <Panel title="SEVERITY DISTRIBUTION"><SeverityChart data={severityData}/></Panel>
                <Panel title="TOP THREAT IPs"><TopThreats threats={stats.top_threats || []}/></Panel>
              </div>
              <Panel title="RECENT DETECTIONS">
                {correlations.length === 0
                  ? <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:20 }}>No detections yet. Submit an event to begin correlation.</div>
                  : correlations.slice(0,8).map((c,i) => <ThreatRow key={c.id||i} threat={c} index={i}/>)
                }
              </Panel>
            </div>
          )}

          {/* DETECTIONS */}
          {tab === "correlations" && (
            <Panel title={`ALL DETECTIONS (${correlations.length})`}>
              {correlations.length === 0
                ? <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:40 }}>No detections recorded yet.</div>
                : correlations.map((c,i) => <ThreatRow key={c.id||i} threat={c} index={i}/>)
              }
            </Panel>
          )}

          {/* IOC DATABASE */}
          {tab === "iocs" && (
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                <input
                  placeholder="Search IOC value..."
                  value={iocSearch}
                  onChange={e => setIocSearch(e.target.value)}
                  style={{
                    background:"var(--panel)", border:"1px solid var(--border)",
                    color:"var(--text)", padding:"8px 14px", borderRadius:2,
                    fontFamily:"var(--font-mono)", fontSize:12, outline:"none", flex:1, maxWidth:300
                  }}
                />
                <select value={iocType} onChange={e => { setIocType(e.target.value); setIocPage(0); }} style={{
                  background:"var(--panel)", border:"1px solid var(--border)",
                  color:"var(--text)", padding:"8px 14px", borderRadius:2,
                  fontFamily:"var(--font-mono)", fontSize:12, outline:"none"
                }}>
                  <option value="">ALL TYPES</option>
                  <option value="ipv4">IPv4</option>
                  <option value="domain">DOMAIN</option>
                  <option value="url">URL</option>
                  <option value="sha256">SHA-256</option>
                  <option value="md5">MD5</option>
                </select>
                <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", marginLeft:"auto" }}>
                  Showing {filteredIocs.length} of {stats.total_iocs?.toLocaleString()} IOCs
                </div>
              </div>
              <Panel title="IOC INDICATOR DATABASE">
                <IOCTable iocs={filteredIocs}/>
                <div style={{ display:"flex", gap:12, justifyContent:"center", marginTop:16 }}>
                  <button onClick={() => setIocPage(p => Math.max(0,p-1))} disabled={iocPage===0} style={{
                    background:"var(--surface)", border:"1px solid var(--border)", color: iocPage===0 ? "var(--muted)" : "var(--accent)",
                    padding:"6px 16px", fontFamily:"var(--font-mono)", fontSize:11, cursor: iocPage===0 ? "default" : "pointer", borderRadius:2
                  }}>← PREV</button>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", padding:"6px 12px" }}>PAGE {iocPage+1}</span>
                  <button onClick={() => setIocPage(p => p+1)} disabled={iocs.length < 50} style={{
                    background:"var(--surface)", border:"1px solid var(--border)", color: iocs.length < 50 ? "var(--muted)" : "var(--accent)",
                    padding:"6px 16px", fontFamily:"var(--font-mono)", fontSize:11, cursor: iocs.length < 50 ? "default" : "pointer", borderRadius:2
                  }}>NEXT →</button>
                </div>
              </Panel>
            </div>
          )}

          {/* SUBMIT EVENT */}
          {tab === "submit" && (
            <div style={{ maxWidth:680 }}>
              <Panel title="SUBMIT NETWORK EVENT FOR CORRELATION">
                <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", marginBottom:20, lineHeight:1.8 }}>
                  Enter a network event to correlate against the IOC database.<br/>
                  Private/loopback IPs are automatically filtered. A PDF report is generated for each event.
                </div>
                <EventForm onResult={(r) => { setEventResult(r); fetchAll(); }}/>
              </Panel>
              {eventResult && (
                <div style={{ marginTop:16 }}>
                  <ResultAlert result={eventResult} onClose={() => setEventResult(null)}/>
                </div>
              )}
              {eventResult?.report && (
                <div style={{ marginTop:12 }}>
                  <a href={`${API}/report/${eventResult.event_id}`} target="_blank" rel="noreferrer" style={{
                    display:"inline-flex", alignItems:"center", gap:8,
                    fontFamily:"var(--font-mono)", fontSize:11, color:"var(--accent3)",
                    border:"1px solid var(--accent3)", padding:"8px 16px", borderRadius:2,
                    textDecoration:"none", transition:"all 0.2s"
                  }}>
                    ⬇ DOWNLOAD PDF REPORT — {eventResult.event_id}
                  </a>
                </div>
              )}
            </div>
          )}

        </main>

        <footer style={{
          borderTop:"1px solid var(--border)", padding:"10px 24px",
          display:"flex", justifyContent:"space-between", alignItems:"center",
          background:"var(--surface)"
        }}>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
            STIX 2.1 THREAT INTELLIGENCE CORRELATION PLATFORM
          </span>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
            <span style={{ color:"var(--accent3)", animation:"blink 1.2s infinite" }}>●</span> API: {API}
          </span>
        </footer>
      </div>
    </>
  );
}