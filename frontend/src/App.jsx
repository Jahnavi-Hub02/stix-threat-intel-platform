import { useState, useEffect, useCallback, useRef } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from "recharts";

// ── Config ─────────────────────────────────────────────────────────
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
    html, body, #root { height:100%; background:var(--bg); color:var(--text); font-family:var(--font-ui); overflow-x:hidden; }
    body::before {
      content:''; position:fixed; inset:0; z-index:9999; pointer-events:none;
      background:repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px);
    }
    ::-webkit-scrollbar { width:4px; }
    ::-webkit-scrollbar-track { background:var(--surface); }
    ::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
    @keyframes pulse-glow { 0%,100%{box-shadow:0 0 8px rgba(0,212,255,0.3);} 50%{box-shadow:0 0 20px rgba(0,212,255,0.7);} }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
    @keyframes slide-in { from{opacity:0;transform:translateY(16px);} to{opacity:1;transform:translateY(0);} }
    @keyframes rotate { from{transform:rotate(0deg);} to{transform:rotate(360deg);} }
    @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }
  `}</style>
);

// ── Auth API helpers ──────────────────────────────────────────────
// Token stored in module-level variable (never localStorage — XSS safe)
let _accessToken = null;

const setToken = (t) => { _accessToken = t; };
const getToken = () => _accessToken;
const clearToken = () => { _accessToken = null; };

// All authenticated fetch calls go through this helper
const apiFetch = async (path, options = {}) => {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { "Authorization": `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };
  const res = await fetch(`${API}${path}`, { ...options, headers });
  return res;
};

// ── Helpers ────────────────────────────────────────────────────────
const sev = (s) => ({ Critical:"--critical", High:"--high", Medium:"--medium", Low:"--low" }[s] || "--muted");
const formatTime = (iso) => iso ? new Date(iso).toLocaleTimeString() : "—";
const formatDate = (iso) => iso ? new Date(iso).toLocaleString() : "—";

// ══════════════════════════════════════════════════════════════════
// LOGIN SCREEN
// ══════════════════════════════════════════════════════════════════
function LoginScreen({ onLogin }) {
  const [mode, setMode]         = useState("login");   // "login" | "register"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole]         = useState("analyst");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  const inputStyle = {
    width:"100%", background:"#0d1117", border:"1px solid #1e2d45",
    color:"#c9d1d9", padding:"12px 16px", borderRadius:4,
    fontFamily:"'Share Tech Mono', monospace", fontSize:13, outline:"none",
    transition:"border-color 0.2s",
  };
  const btnStyle = {
    width:"100%", background:"linear-gradient(90deg,#00d4ff22,#00d4ff11)",
    border:"1px solid #00d4ff", color:"#00d4ff", padding:"13px",
    fontFamily:"'Rajdhani',sans-serif", fontSize:15, fontWeight:700,
    letterSpacing:3, cursor:"pointer", borderRadius:4,
    transition:"all 0.2s", marginTop:8,
  };

  const submit = async () => {
    if (!username.trim() || !password.trim()) { setError("Username and password required"); return; }
    setLoading(true); setError("");
    try {
      if (mode === "register") {
        const r = await fetch(`${API}/auth/register`, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify({ username, password, role }),
        });
        const d = await r.json();
        if (!r.ok) { setError(d.detail || "Registration failed"); return; }
        setMode("login"); setError(""); setPassword("");
        return;
      }
      // Login
      const r = await fetch(`${API}/auth/login`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ username, password }),
      });
      const d = await r.json();
      if (!r.ok) { setError(d.detail || "Login failed"); return; }
      setToken(d.access_token);
      onLogin({ username: d.username, role: d.role, token: d.access_token });
    } catch {
      setError("Cannot reach the API server. Make sure it is running on port 8000.");
    } finally { setLoading(false); }
  };

  const handleKey = (e) => { if (e.key === "Enter") submit(); };

  return (
    <div style={{
      minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
      background:"var(--bg)", animation:"fadeIn 0.4s ease",
    }}>
      <GlobalStyles/>
      <div style={{
        width:380, background:"var(--surface)", border:"1px solid var(--border)",
        borderRadius:8, padding:40, boxShadow:"0 0 40px rgba(0,212,255,0.08)",
      }}>
        {/* Logo */}
        <div style={{ textAlign:"center", marginBottom:32 }}>
          <svg width="44" height="44" viewBox="0 0 28 28" style={{ display:"block", margin:"0 auto 12px" }}>
            <polygon points="14,2 26,8 26,20 14,26 2,20 2,8" fill="none" stroke="#00d4ff" strokeWidth="1.5"/>
            <polygon points="14,6 22,10 22,18 14,22 6,18 6,10" fill="none" stroke="#00d4ff" strokeWidth="0.8" opacity="0.5"/>
            <circle cx="14" cy="14" r="3" fill="#00d4ff"/>
          </svg>
          <div style={{ fontFamily:"var(--font-head)", fontSize:18, fontWeight:700, letterSpacing:3, color:"var(--accent)" }}>
            STIX THREAT INTEL
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", marginTop:4 }}>
            v2.5.0 — JWT SECURED
          </div>
        </div>

        {/* Mode toggle */}
        <div style={{ display:"flex", borderBottom:"1px solid var(--border)", marginBottom:28 }}>
          {["login","register"].map(m => (
            <button key={m} onClick={() => { setMode(m); setError(""); }} style={{
              flex:1, background:"none", border:"none", cursor:"pointer",
              fontFamily:"var(--font-head)", fontSize:13, fontWeight:700, letterSpacing:2,
              color: mode === m ? "var(--accent)" : "var(--muted)",
              padding:"10px 0",
              borderBottom: mode === m ? "2px solid var(--accent)" : "2px solid transparent",
              transition:"all 0.2s",
            }}>{m.toUpperCase()}</button>
          ))}
        </div>

        {/* Fields */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          <input
            style={inputStyle} placeholder="Username"
            value={username} onChange={e => setUsername(e.target.value)}
            onKeyDown={handleKey} autoFocus
          />
          <input
            style={inputStyle} placeholder="Password" type="password"
            value={password} onChange={e => setPassword(e.target.value)}
            onKeyDown={handleKey}
          />
          {mode === "register" && (
            <select value={role} onChange={e => setRole(e.target.value)} style={inputStyle}>
              <option value="viewer">Viewer — read only</option>
              <option value="analyst">Analyst — submit events + train ML</option>
              <option value="admin">Admin — full access</option>
            </select>
          )}
          {error && (
            <div style={{
              fontFamily:"var(--font-mono)", fontSize:11, color:"var(--critical)",
              background:"rgba(255,60,110,0.08)", border:"1px solid rgba(255,60,110,0.2)",
              padding:"10px 14px", borderRadius:4,
            }}>{error}</div>
          )}
          <button style={btnStyle} onClick={submit} disabled={loading}>
            {loading ? "..." : mode === "login" ? "AUTHENTICATE" : "CREATE ACCOUNT"}
          </button>
        </div>

        {mode === "login" && (
          <div style={{
            marginTop:20, fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)",
            textAlign:"center", lineHeight:1.8, borderTop:"1px solid var(--border)", paddingTop:16,
          }}>
            No account? Register above first.<br/>
            Roles: <span style={{color:"var(--low)"}}>viewer</span> · <span style={{color:"var(--accent)"}}>analyst</span> · <span style={{color:"var(--critical)"}}>admin</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// EXISTING DASHBOARD COMPONENTS (unchanged)
// ══════════════════════════════════════════════════════════════════

function TopBar({ live, lastUpdate, onRefresh, loading, user, onLogout }) {
  const [tick, setTick] = useState(true);
  useEffect(() => { const t = setInterval(() => setTick(p => !p), 1000); return () => clearInterval(t); }, []);
  return (
    <header style={{
      background:"linear-gradient(90deg,#0d1117 0%,#111827 50%,#0d1117 100%)",
      borderBottom:"1px solid var(--border)", padding:"0 24px", height:56,
      display:"flex", alignItems:"center", justifyContent:"space-between",
      position:"sticky", top:0, zIndex:100, boxShadow:"0 2px 20px rgba(0,212,255,0.1)"
    }}>
      <div style={{ display:"flex", alignItems:"center", gap:16 }}>
        <svg width="28" height="28" viewBox="0 0 28 28">
          <polygon points="14,2 26,8 26,20 14,26 2,20 2,8" fill="none" stroke="var(--accent)" strokeWidth="1.5"/>
          <polygon points="14,6 22,10 22,18 14,22 6,18 6,10" fill="none" stroke="var(--accent)" strokeWidth="0.8" opacity="0.5"/>
          <circle cx="14" cy="14" r="3" fill="var(--accent)"/>
        </svg>
        <div>
          <div style={{ fontFamily:"var(--font-head)", fontSize:16, fontWeight:700, letterSpacing:3, color:"var(--accent)" }}>
            STIX THREAT INTELLIGENCE
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--muted)", letterSpacing:2 }}>
            CORRELATION PLATFORM v2.5.0
          </div>
        </div>
      </div>
      <div style={{ display:"flex", alignItems:"center", gap:20 }}>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
          <span style={{ color: live ? "var(--accent3)" : "var(--critical)", animation:"blink 1.2s infinite" }}>●</span>
          {" "}{live ? "LIVE" : "OFFLINE"} · {lastUpdate ? formatTime(lastUpdate) : "—"}
        </div>
        {/* Auth info */}
        {user && (
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <span style={{
              fontFamily:"var(--font-mono)", fontSize:10,
              color: user.role === "admin" ? "var(--critical)" : user.role === "analyst" ? "var(--accent)" : "var(--low)",
              border:`1px solid currentColor`, padding:"2px 8px", borderRadius:2,
            }}>
              {user.username.toUpperCase()} [{user.role.toUpperCase()}]
            </span>
            <button onClick={onLogout} style={{
              background:"none", border:"1px solid var(--border)", color:"var(--muted)",
              fontFamily:"var(--font-mono)", fontSize:10, padding:"3px 10px", cursor:"pointer",
              borderRadius:2, transition:"all 0.2s",
            }}>LOGOUT</button>
          </div>
        )}
        <button onClick={onRefresh} disabled={loading} style={{
          background:"none", border:"1px solid var(--border)", color:"var(--accent)",
          fontFamily:"var(--font-mono)", fontSize:10, padding:"5px 14px",
          cursor:"pointer", letterSpacing:1, borderRadius:2, transition:"all 0.2s",
          animation: loading ? "rotate 1s linear infinite" : "none",
        }}>⟳ REFRESH</button>
      </div>
    </header>
  );
}

function Panel({ title, children, style={} }) {
  return (
    <div style={{
      background:"var(--panel)", border:"1px solid var(--border)",
      borderRadius:4, overflow:"hidden", ...style
    }}>
      <div style={{
        padding:"12px 18px", borderBottom:"1px solid var(--border)",
        fontFamily:"var(--font-head)", fontSize:12, fontWeight:700,
        letterSpacing:3, color:"var(--accent)", display:"flex", alignItems:"center", gap:8
      }}>
        <span style={{ width:6, height:6, background:"var(--accent)", borderRadius:"50%", display:"inline-block" }}/>
        {title}
      </div>
      <div style={{ padding:18 }}>{children}</div>
    </div>
  );
}

function StatCard({ label, value, sub, color, icon, delay=0 }) {
  return (
    <div style={{
      background:"var(--panel)", border:`1px solid ${color}22`,
      borderRadius:4, padding:"20px 22px",
      animation:`slide-in 0.4s ease ${delay}s both`,
      borderLeft:`3px solid ${color}`,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", letterSpacing:2, marginBottom:8 }}>{label}</div>
          <div style={{ fontFamily:"var(--font-head)", fontSize:36, fontWeight:800, color, lineHeight:1 }}>
            {value?.toLocaleString() ?? "—"}
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", marginTop:6 }}>{sub}</div>
        </div>
        <div style={{ fontSize:24, color:`${color}66` }}>{icon}</div>
      </div>
    </div>
  );
}

function SeverityChart({ data }) {
  const COLORS = { Critical:"#ff3c6e", High:"#ff8c42", Medium:"#ffd700", Low:"#00ff9f" };
  const chartData = Object.entries(data).map(([name, value]) => ({ name, value, fill: COLORS[name] }));
  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={chartData} barSize={32}>
        <XAxis dataKey="name" tick={{ fontFamily:"var(--font-mono)", fontSize:10, fill:"#4a5568" }} axisLine={false} tickLine={false}/>
        <YAxis tick={{ fontFamily:"var(--font-mono)", fontSize:10, fill:"#4a5568" }} axisLine={false} tickLine={false}/>
        <Tooltip
          contentStyle={{ background:"#111827", border:"1px solid #1e2d45", fontFamily:"var(--font-mono)", fontSize:11 }}
          cursor={{ fill:"rgba(0,212,255,0.05)" }}
        />
        <Bar dataKey="value" radius={[2,2,0,0]}>
          {chartData.map((e,i) => <Cell key={i} fill={e.fill}/>)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function TopThreats({ threats }) {
  if (!threats?.length) return (
    <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:20 }}>
      No threat data yet
    </div>
  );
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {threats.slice(0,5).map((t,i) => (
        <div key={i} style={{
          display:"flex", justifyContent:"space-between", alignItems:"center",
          padding:"8px 12px", background:"var(--surface)", borderRadius:3, border:"1px solid var(--border)"
        }}>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text)" }}>{t.ip}</span>
          <span style={{
            fontFamily:"var(--font-mono)", fontSize:10, padding:"2px 8px",
            background:`var(${sev(t.severity)})22`, color:`var(${sev(t.severity)})`, borderRadius:2
          }}>{t.count} hits</span>
        </div>
      ))}
    </div>
  );
}

function ThreatRow({ threat, index }) {
  const sevColor = `var(${sev(threat.severity)})`;
  return (
    <div style={{
      display:"grid", gridTemplateColumns:"1fr 1fr 120px 90px 80px",
      gap:12, padding:"10px 14px", borderBottom:"1px solid var(--border)",
      animation:`slide-in 0.3s ease ${index*0.03}s both`,
      fontFamily:"var(--font-mono)", fontSize:11,
    }}>
      <span style={{ color:"var(--text)" }}>{threat.matched_ip || threat.event_id}</span>
      <span style={{ color:"var(--muted)" }}>{threat.match_type?.replace(/_/g," ").toUpperCase() || "—"}</span>
      <span style={{ color:"var(--muted)" }}>{threat.mitre_tactic || "—"}</span>
      <span style={{
        color: sevColor, background:`${sevColor}18`,
        padding:"2px 8px", borderRadius:2, textAlign:"center", fontSize:10
      }}>{threat.severity || "—"}</span>
      <span style={{ color:"var(--accent)" }}>{threat.risk_score ? `${threat.risk_score.toFixed(0)}` : "—"}</span>
    </div>
  );
}

function IOCTable({ iocs }) {
  if (!iocs.length) return (
    <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:30 }}>
      No IOCs found
    </div>
  );
  const typeColor = { ipv4:"#00d4ff", domain:"#00ff9f", url:"#ffd700", sha256:"#ff8c42", md5:"#ff3c6e" };
  return (
    <div style={{ overflowX:"auto" }}>
      <table style={{ width:"100%", borderCollapse:"collapse" }}>
        <thead>
          <tr style={{ borderBottom:"2px solid var(--border)" }}>
            {["TYPE","VALUE","CONFIDENCE","SOURCE","ADDED"].map(h => (
              <th key={h} style={{ padding:"8px 12px", textAlign:"left", fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", letterSpacing:1 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={ioc.id || i} style={{ borderBottom:"1px solid var(--border)22" }}>
              <td style={{ padding:"9px 12px" }}>
                <span style={{
                  fontFamily:"var(--font-mono)", fontSize:10, padding:"2px 8px",
                  background:`${typeColor[ioc.ioc_type]||"#4a5568"}18`,
                  color: typeColor[ioc.ioc_type]||"var(--muted)", borderRadius:2
                }}>{ioc.ioc_type?.toUpperCase()}</span>
              </td>
              <td style={{ padding:"9px 12px", fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text)", maxWidth:280, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ioc.ioc_value}</td>
              <td style={{ padding:"9px 12px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <div style={{ flex:1, height:4, background:"var(--border)", borderRadius:2, maxWidth:80 }}>
                    <div style={{ width:`${ioc.confidence||0}%`, height:"100%", background:`var(${sev(ioc.confidence>80?"Critical":ioc.confidence>60?"High":"Medium")})`, borderRadius:2 }}/>
                  </div>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>{ioc.confidence}%</span>
                </div>
              </td>
              <td style={{ padding:"9px 12px", color:"var(--muted)", fontFamily:"var(--font-mono)", fontSize:10 }}>{ioc.source}</td>
              <td style={{ padding:"9px 12px", color:"var(--muted)", fontFamily:"var(--font-mono)", fontSize:10 }}>{ioc.created_at ? new Date(ioc.created_at).toLocaleDateString() : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ResultAlert({ result, onClose }) {
  const isThreats  = result.status === "threat_detected"  || result.status === "confirmed_threat";
  const isAnomaly  = result.status === "anomaly_detected" || result.status === "confirmed_threat";
  const borderColor = isThreats ? "var(--critical)" : isAnomaly ? "var(--high)" : "var(--accent3)";
  return (
    <div style={{
      background:"var(--panel)", border:`1px solid ${borderColor}`,
      borderRadius:4, padding:20, animation:"slide-in 0.3s ease",
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
        <span style={{ fontFamily:"var(--font-head)", fontSize:14, fontWeight:700, letterSpacing:2, color: borderColor }}>
          {result.status === "confirmed_threat" && "⚠ CONFIRMED THREAT"}
          {result.status === "threat_detected"  && "⚠ THREAT DETECTED"}
          {result.status === "anomaly_detected" && "◈ ANOMALY DETECTED"}
          {result.status === "benign"            && "✓ BENIGN"}
        </span>
        <button onClick={onClose} style={{ background:"none", border:"none", color:"var(--muted)", cursor:"pointer", fontSize:16 }}>✕</button>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))", gap:12 }}>
        {[
          ["Event ID",     result.event_id],
          ["Final Risk",   `${result.final_risk_score ?? "—"}/100`],
          ["Severity",     result.final_severity],
          ["IOC Matches",  result.ioc_analysis?.matches_found ?? 0],
          ["ML Score",     result.ml_analysis?.anomaly_score != null ? result.ml_analysis.anomaly_score.toFixed(3) : "—"],
          ["ML Status",    result.ml_analysis?.ml_status ?? "—"],
        ].map(([k,v]) => (
          <div key={k} style={{ fontFamily:"var(--font-mono)", fontSize:11 }}>
            <div style={{ color:"var(--muted)", fontSize:9, letterSpacing:1, marginBottom:3 }}>{k}</div>
            <div style={{ color:"var(--text)" }}>{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── EventForm — uses apiFetch so token is included ────────────────
function EventForm({ onResult }) {
  const [form, setForm] = useState({
    event_id: `evt-${Date.now().toString().slice(-4)}`,
    source_ip: "", destination_ip: "",
    source_port: "", destination_port: "", protocol: "TCP"
  });
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  const submit = async () => {
    if (!form.source_ip || !form.destination_ip) { setError("Source and Destination IP required"); return; }
    setLoading(true); setError("");
    try {
      const res = await apiFetch("/event", {
        method: "POST",
        body: JSON.stringify({
          ...form,
          source_port:      form.source_port      ? parseInt(form.source_port)      : null,
          destination_port: form.destination_port ? parseInt(form.destination_port) : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.detail || "Submission failed"); return; }
      onResult(data);
      setForm(f => ({ ...f, event_id:`evt-${Date.now().toString().slice(-4)}`, source_ip:"", destination_ip:"" }));
    } catch { setError("API connection failed."); }
    finally { setLoading(false); }
  };

  const inp = (key, placeholder, type="text") => (
    <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
      <label style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)", letterSpacing:1 }}>
        {key.replace(/_/g," ").toUpperCase()}
      </label>
      <input
        type={type} placeholder={placeholder} value={form[key]}
        onChange={e => setForm(f => ({...f, [key]: e.target.value}))}
        style={{ background:"var(--surface)", border:"1px solid var(--border)", color:"var(--text)",
          padding:"10px 14px", borderRadius:3, fontFamily:"var(--font-mono)", fontSize:12, outline:"none" }}
      />
    </div>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
        {inp("event_id","evt-0001")}
        {inp("protocol","TCP")}
        {inp("source_ip","192.168.1.10")}
        {inp("destination_ip","185.220.101.45")}
        {inp("source_port","54321","number")}
        {inp("destination_port","443","number")}
      </div>
      {error && <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--critical)", padding:"8px 12px", background:"rgba(255,60,110,0.08)", borderRadius:3 }}>{error}</div>}
      <button onClick={submit} disabled={loading} style={{
        background:"linear-gradient(90deg,rgba(0,212,255,0.15),rgba(0,212,255,0.08))",
        border:"1px solid var(--accent)", color:"var(--accent)", padding:"12px",
        fontFamily:"var(--font-head)", fontSize:14, fontWeight:700, letterSpacing:3,
        cursor:"pointer", borderRadius:3, transition:"all 0.2s", opacity: loading ? 0.7 : 1,
      }}>
        {loading ? "ANALYZING..." : "▶ SUBMIT FOR CORRELATION"}
      </button>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// MAIN APP
// ══════════════════════════════════════════════════════════════════
export default function App() {
  const [user, setUser]               = useState(null);  // null = not logged in
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
  const [mlStatus, setMlStatus]       = useState(null);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    clearToken();
    setUser(null);
    setMetrics(null); setCorr([]); setIocs([]);
  };

  const fetchAll = useCallback(async () => {
    if (!getToken()) return;
    setLoading(true);
    try {
      const [mRes, cRes, iRes, mlRes] = await Promise.all([
        apiFetch("/metrics"),
        apiFetch("/correlations?limit=20"),
        apiFetch(`/iocs?limit=50&offset=${iocPage * 50}${iocType ? `&ioc_type=${iocType}` : ""}`),
        apiFetch("/ml/status"),
      ]);
      if (mRes.ok) { setMetrics(await mRes.json()); setLive(true); }
      else if (mRes.status === 401) { handleLogout(); return; }
      if (cRes.ok) { const d = await cRes.json(); setCorr(d.results || []); }
      if (iRes.ok) { const d = await iRes.json(); setIocs(d.iocs || []); }
      if (mlRes.ok) { setMlStatus(await mlRes.json()); }
      setLastUpdate(new Date().toISOString());
    } catch { setLive(false); }
    finally { setLoading(false); }
  }, [iocPage, iocType, user]);

  useEffect(() => { if (user) fetchAll(); }, [fetchAll, user]);
  useEffect(() => {
    if (!user) return;
    const t = setInterval(fetchAll, 30000);
    return () => clearInterval(t);
  }, [fetchAll, user]);

  // Show login screen if not authenticated
  if (!user) {
    return <LoginScreen onLogin={handleLogin}/>;
  }

  const stats = metrics?.data || metrics?.statistics || {};
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
      background:"none", border:"none", cursor:"pointer",
      fontFamily:"var(--font-head)", fontSize:13, fontWeight:600, letterSpacing:2,
      color: tab === id ? "var(--accent)" : "var(--muted)",
      padding:"18px 16px",
      borderBottom: tab === id ? "2px solid var(--accent)" : "2px solid transparent",
      transition:"all 0.2s",
    }}>{label}</button>
  );

  return (
    <>
      <GlobalStyles/>
      <div style={{ minHeight:"100vh", display:"flex", flexDirection:"column" }}>
        <TopBar live={live} lastUpdate={lastUpdate} onRefresh={fetchAll} loading={loading} user={user} onLogout={handleLogout}/>

        <div style={{ background:"var(--surface)", borderBottom:"1px solid var(--border)", padding:"0 24px", display:"flex", gap:4 }}>
          {navItem("overview",    "OVERVIEW")}
          {navItem("correlations","DETECTIONS")}
          {navItem("iocs",        "IOC DATABASE")}
          {navItem("submit",      "SUBMIT EVENT")}
          {navItem("ml",          "ML STATUS")}
        </div>

        <main style={{ flex:1, padding:24, maxWidth:1400, width:"100%", margin:"0 auto" }}>

          {/* ── OVERVIEW ── */}
          {tab === "overview" && (
            <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))", gap:16 }}>
                <StatCard label="TOTAL IOCs"      value={stats.total_iocs}           sub="Threat indicators stored"  color="var(--accent)"  icon="◈" delay={0}/>
                <StatCard label="EVENTS LOGGED"   value={stats.total_events}         sub="Network events analyzed"   color="var(--accent3)" icon="◉" delay={0.05}/>
                <StatCard label="CORRELATIONS"    value={stats.total_correlations}   sub="IOC matches detected"      color="var(--high)"    icon="◎" delay={0.1}/>
                <StatCard label="CRITICAL ALERTS" value={stats.severity_breakdown?.critical ?? 0} sub="Immediate action required" color="var(--critical)" icon="⬡" delay={0.15}/>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
                <Panel title="SEVERITY DISTRIBUTION"><SeverityChart data={severityData}/></Panel>
                <Panel title="TOP THREAT IPs"><TopThreats threats={stats.top_threats || []}/></Panel>
              </div>
              <Panel title="RECENT DETECTIONS">
                {correlations.length === 0
                  ? <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:20 }}>No detections yet.</div>
                  : correlations.slice(0,8).map((c,i) => <ThreatRow key={c.id||i} threat={c} index={i}/>)
                }
              </Panel>
            </div>
          )}

          {/* ── DETECTIONS ── */}
          {tab === "correlations" && (
            <Panel title={`ALL DETECTIONS (${correlations.length})`}>
              {correlations.length === 0
                ? <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", textAlign:"center", padding:40 }}>No detections recorded yet.</div>
                : correlations.map((c,i) => <ThreatRow key={c.id||i} threat={c} index={i}/>)
              }
            </Panel>
          )}

          {/* ── IOC DATABASE ── */}
          {tab === "iocs" && (
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                <input placeholder="Search IOC value..." value={iocSearch}
                  onChange={e => setIocSearch(e.target.value)}
                  style={{ background:"var(--panel)", border:"1px solid var(--border)", color:"var(--text)",
                    padding:"8px 14px", borderRadius:2, fontFamily:"var(--font-mono)", fontSize:12, outline:"none", flex:1, maxWidth:300 }}/>
                <select value={iocType} onChange={e => { setIocType(e.target.value); setIocPage(0); }}
                  style={{ background:"var(--panel)", border:"1px solid var(--border)", color:"var(--text)",
                    padding:"8px 14px", borderRadius:2, fontFamily:"var(--font-mono)", fontSize:12, outline:"none" }}>
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
                  <button onClick={() => setIocPage(p => Math.max(0,p-1))} disabled={iocPage===0} style={{ background:"var(--surface)", border:"1px solid var(--border)", color: iocPage===0?"var(--muted)":"var(--accent)", padding:"6px 16px", fontFamily:"var(--font-mono)", fontSize:11, cursor: iocPage===0?"default":"pointer", borderRadius:2 }}>← PREV</button>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", padding:"6px 12px" }}>PAGE {iocPage+1}</span>
                  <button onClick={() => setIocPage(p => p+1)} disabled={iocs.length<50} style={{ background:"var(--surface)", border:"1px solid var(--border)", color: iocs.length<50?"var(--muted)":"var(--accent)", padding:"6px 16px", fontFamily:"var(--font-mono)", fontSize:11, cursor: iocs.length<50?"default":"pointer", borderRadius:2 }}>NEXT →</button>
                </div>
              </Panel>
            </div>
          )}

          {/* ── SUBMIT EVENT ── */}
          {tab === "submit" && (
            <div style={{ maxWidth:680 }}>
              {user.role === "viewer" && (
                <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--high)", background:"rgba(255,140,66,0.08)", border:"1px solid rgba(255,140,66,0.2)", padding:"10px 16px", borderRadius:4, marginBottom:16 }}>
                  ⚠ Your role is <b>viewer</b>. You need <b>analyst</b> or <b>admin</b> role to submit events.
                </div>
              )}
              <Panel title="SUBMIT NETWORK EVENT FOR CORRELATION">
                <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", marginBottom:20, lineHeight:1.8 }}>
                  Enter a network event to correlate against the IOC database + ML anomaly detection.<br/>
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
                    textDecoration:"none",
                  }}>
                    ⬇ DOWNLOAD PDF REPORT — {eventResult.event_id}
                  </a>
                </div>
              )}
            </div>
          )}

          {/* ── ML STATUS ── */}
          {tab === "ml" && (
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))", gap:16 }}>
                <StatCard label="MODEL TRAINED"    value={mlStatus?.model_trained ? "YES" : "NO"} sub="Isolation Forest ready" color={mlStatus?.model_trained ? "var(--accent3)" : "var(--muted)"} icon="⬡" delay={0}/>
                <StatCard label="EVENTS COLLECTED" value={mlStatus?.events_collected ?? "—"}       sub={`Min needed: ${mlStatus?.min_train_samples ?? "—"}`} color="var(--accent)" icon="◈" delay={0.05}/>
                <StatCard label="CONTAMINATION"    value={mlStatus?.contamination ?? "—"}          sub="Expected anomaly rate"    color="var(--high)"    icon="◎" delay={0.1}/>
                <StatCard label="ML EVENTS"        value={stats.ml?.total_ml_events ?? "—"}        sub={`${stats.ml?.total_anomalies ?? 0} anomalies`}  color="var(--critical)" icon="◉" delay={0.15}/>
              </div>
              <Panel title="ISOLATION FOREST — FEATURE NAMES">
                <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
                  {(mlStatus?.feature_names || []).map((f,i) => (
                    <span key={i} style={{
                      fontFamily:"var(--font-mono)", fontSize:11, padding:"4px 12px",
                      background:"var(--surface)", border:"1px solid var(--border)",
                      color:"var(--accent)", borderRadius:3,
                    }}>{f}</span>
                  ))}
                </div>
              </Panel>
              {user.role !== "viewer" && (
                <Panel title="MANUAL TRAINING">
                  <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--muted)", marginBottom:16 }}>
                    Force-train the model even if below the {mlStatus?.min_train_samples}-event threshold.
                  </div>
                  <button onClick={async () => {
                    const r = await apiFetch("/ml/train?force=true", { method:"POST" });
                    const d = await r.json();
                    alert(`Training result: ${d.status}\n${d.message || JSON.stringify(d)}`);
                    fetchAll();
                  }} style={{
                    background:"linear-gradient(90deg,rgba(0,212,255,0.15),rgba(0,212,255,0.08))",
                    border:"1px solid var(--accent)", color:"var(--accent)",
                    padding:"10px 24px", fontFamily:"var(--font-head)", fontSize:13,
                    fontWeight:700, letterSpacing:3, cursor:"pointer", borderRadius:3,
                  }}>⟳ FORCE TRAIN MODEL</button>
                </Panel>
              )}
            </div>
          )}

        </main>

        <footer style={{
          borderTop:"1px solid var(--border)", padding:"10px 24px",
          display:"flex", justifyContent:"space-between", alignItems:"center",
          background:"var(--surface)",
        }}>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
            STIX 2.1 THREAT INTELLIGENCE CORRELATION PLATFORM v2.5.0
          </span>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--muted)" }}>
            <span style={{ color:"var(--accent3)", animation:"blink 1.2s infinite" }}>●</span> API: {API}
          </span>
        </footer>
      </div>
    </>
  );
}