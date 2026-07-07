"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";

interface AgentStep {
  type: string;
  content: string;
  tool_used?: string;
  command_executed?: string;
  audit_status?: string;
}

interface AuditData {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
}

interface VulnerabilityData {
  id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  description: string;
  remediation: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-neutral-500/20 text-neutral-400 border-neutral-500/30",
};

const STEP_ICONS: Record<string, { icon: string; color: string }> = {
  thought: { icon: "🧠", color: "text-purple-400" },
  action: { icon: "⚡", color: "text-[#84cc16]" },
  observation: { icon: "👁", color: "text-blue-400" },
  error: { icon: "❌", color: "text-red-400" },
  done: { icon: "✅", color: "text-green-400" },
};

export default function AuditDetailPage() {
  const params = useParams();
  const router = useRouter();
  const auditId = params.id as string;
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [status, setStatus] = useState<string>("idle");
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityData[]>([]);
  const [openPorts, setOpenPorts] = useState<any[]>([]);
  const [attacks, setAttacks] = useState<any[]>([]);
  const [audit, setAudit] = useState<AuditData | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pendingContextRef = useRef<string | null>(null);
  const findingsRefreshRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [guidance, setGuidance] = useState("");
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }
    fetchAudit();
    fetchFindings();
    return () => {
      if (findingsRefreshRef.current) clearTimeout(findingsRefreshRef.current);
    };
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [steps]);

  const fetchAudit = async () => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/audits/${auditId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAudit(data);
        setStatus(data.status);
      }
    } catch (e) {
      console.warn("audit fetch failed", e);
    }
  };

  const fetchFindings = async () => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/audits/${auditId}/findings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setVulnerabilities(data.vulnerabilities || []);
        setOpenPorts(data.open_ports || []);
        setAttacks(data.suggested_attacks || []);
        if (!running && Array.isArray(data.logs)) {
          const mappedLogs: AgentStep[] = data.logs.map((log: any) => ({
            type: log.step_type,
            content: log.content,
            tool_used: log.tool_used,
            command_executed: log.command_executed,
          }));
          setSteps(mappedLogs);
        }
      }
    } catch (e) {
      console.warn("findings fetch failed", e);
    }
  };

  const scheduleFindingsRefresh = () => {
    if (findingsRefreshRef.current) clearTimeout(findingsRefreshRef.current);
    findingsRefreshRef.current = setTimeout(() => {
      fetchFindings().catch(() => {});
    }, 1500);
  };

  const startAgent = () => {
    if (!token) return;
    setRunning(true);

    const ws = new WebSocket(`ws://localhost:8000/api/v1/audits/${auditId}/stream?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      if (pendingContextRef.current) {
        ws.send(JSON.stringify({ type: "guidance", content: pendingContextRef.current }));
        pendingContextRef.current = null;
      }
    };

    ws.onmessage = (event) => {
      const data: AgentStep = JSON.parse(event.data);
      setSteps((prev) => [...prev, data]);
      if (data.audit_status) {
        setStatus(data.audit_status);
      }
      if (data.type === "done") {
        setRunning(false);
        setConnected(false);
        fetchFindings();
        fetchAudit();
      }
      scheduleFindingsRefresh();
    };

    ws.onclose = () => {
      setConnected(false);
      setRunning(false);
      if (findingsRefreshRef.current) clearTimeout(findingsRefreshRef.current);
      fetchFindings().catch(() => {});
      fetchAudit().catch(() => {});
    };

    ws.onerror = (e) => {
      setConnected(false);
      setRunning(false);
      console.warn("websocket error", e);
    };
  };

  const sendDecision = (decision: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ decision }));
    }
  };

  const sendGuidance = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN && guidance.trim()) {
      wsRef.current.send(JSON.stringify({ type: "guidance", content: guidance.trim() }));
      setSteps((prev) => [...prev, { type: "thought", content: `📝 Auditor: ${guidance.trim()}`, audit_status: "scanning" }]);
      setGuidance("");
    }
  };

  const startAgentWithContext = () => {
    if (!guidance.trim()) return;
    pendingContextRef.current = guidance.trim();
    setGuidance("");
    startAgent();
  };

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-[#0a0a0a] relative">
      {/* Background effects */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[#84cc16]/3 rounded-full blur-[150px]" />

      {/* Navbar */}
      <nav className="relative z-10 flex-shrink-0 border-b border-[#262626] bg-[#0a0a0a]/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => router.push("/dashboard")}
              className="text-neutral-500 hover:text-white transition-colors"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
              </svg>
            </button>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#84cc16] flex items-center justify-center">
                <svg className="w-5 h-5 text-[#0a0a0a]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <span className="text-lg font-bold text-white">Auditoría</span>
              <span className="text-xs text-neutral-600 font-mono">{auditId.slice(0, 8)}</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {connected && (
              <span className="flex items-center gap-1.5 text-xs text-[#84cc16]">
                <span className="w-2 h-2 rounded-full bg-[#84cc16] animate-pulse" />
                Conectado
              </span>
            )}
          </div>
        </div>
      </nav>

      <main className="relative z-10 max-w-7xl w-full mx-auto px-6 py-6 flex-1 min-h-0 flex flex-col overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
          {/* Terminal - Agent Stream */}
          <div className="lg:col-span-2 h-full min-h-0 flex flex-col">
            <div className="bg-[#111111]/80 border border-[#262626] rounded-2xl overflow-hidden h-full min-h-0 flex flex-col">
              {/* Terminal header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#262626] bg-[#0a0a0a]/50">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                  </div>
                  <span className="text-xs text-neutral-500 ml-2 font-mono">ai-audit-agent</span>
                </div>
                {!running && (
                  <button
                    onClick={startAgent}
                    className="px-3 py-1.5 bg-[#84cc16] hover:bg-[#a3e635] text-[#0a0a0a] font-semibold rounded-lg text-xs transition-all flex items-center gap-1.5"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
                    </svg>
                    Iniciar agente
                  </button>
                )}
                {running && (
                  <button
                    onClick={() => sendDecision("stop")}
                    className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 font-semibold rounded-lg text-xs transition-all flex items-center gap-1.5"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 7.5A2.25 2.25 0 017.5 5.25h9a2.25 2.25 0 012.25 2.25v9a2.25 2.25 0 01-2.25 2.25h-9a2.25 2.25 0 01-2.25-2.25v-9z" />
                    </svg>
                    Detener
                  </button>
                )}
              </div>

              {/* Terminal body */}
              <div
                ref={terminalRef}
                className="p-4 flex-1 min-h-0 overflow-y-auto font-mono text-sm space-y-3"
              >
                {steps.length === 0 && !running && (
                  <div className="text-center text-neutral-600 py-20">
                    <p className="mb-2">Presiona &quot;Iniciar agente&quot; para comenzar la auditoría</p>
                    <p className="text-xs">El agente IA analizará el objetivo usando herramientas de pentesting</p>
                  </div>
                )}

                {steps.map((step, i) => {
                  const info = STEP_ICONS[step.type] || STEP_ICONS.thought;
                  return (
                    <div key={i} className="flex gap-3">
                      <span className="mt-0.5 flex-shrink-0">{info.icon}</span>
                      <div className="flex-1 min-w-0">
                        <span className={`text-xs font-semibold uppercase ${info.color}`}>
                          {step.type}
                        </span>
                        {step.command_executed && (
                          <div className="mt-1 px-3 py-1.5 bg-[#0a0a0a] rounded border border-[#262626] text-[#84cc16] text-xs">
                            $ {step.command_executed}
                          </div>
                        )}
                        <pre className="mt-1 text-neutral-300 whitespace-pre-wrap break-words text-xs leading-relaxed">
                          {step.content}
                        </pre>
                      </div>
                    </div>
                  );
                })}

                {running && status !== "awaiting_decision" && (
                  <div className="flex items-center gap-2 text-[#84cc16]">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    <span className="text-xs">Agente trabajando...</span>
                  </div>
                )}
              </div>

              {/* Decision buttons */}
              {status === "awaiting_decision" && running && (
                <div className="px-4 py-3 border-t border-[#262626] bg-[#0a0a0a]/50">
                  <p className="text-xs text-yellow-400 mb-3 font-medium">
                    ⚠️ Vulnerabilidad detectada — ¿Qué deseas hacer?
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => sendDecision("continue")}
                      className="px-4 py-2 bg-[#84cc16]/20 hover:bg-[#84cc16]/30 text-[#84cc16] border border-[#84cc16]/30 rounded-lg text-xs font-medium transition-all"
                    >
                      Continuar escaneando
                    </button>
                    <button
                      onClick={() => sendDecision("deeper")}
                      className="px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 border border-orange-500/30 rounded-lg text-xs font-medium transition-all"
                    >
                      Profundizar
                    </button>
                    <button
                      onClick={() => sendDecision("skip")}
                      className="px-4 py-2 bg-neutral-500/20 hover:bg-neutral-500/30 text-neutral-400 border border-neutral-500/30 rounded-lg text-xs font-medium transition-all"
                    >
                      Saltar
                    </button>
                    <button
                      onClick={() => sendDecision("stop")}
                      className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium transition-all"
                    >
                      Detener
                    </button>
                  </div>
                </div>
              )}

              {/* Guidance input */}
              <div className="px-4 py-3 border-t border-[#262626] bg-[#0a0a0a]/50">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={guidance}
                    onChange={(e) => setGuidance(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && (running ? sendGuidance() : startAgentWithContext())}
                    placeholder={
                      running
                        ? "Guía al agente: 'escanea puerto 8080', 'prueba SQLi en /login'..."
                        : "Contexto para reanudar: qué debe hacer el agente al iniciar..."
                    }
                    className="flex-1 px-3 py-2 bg-[#0a0a0a] border border-[#262626] rounded-lg text-white text-xs placeholder-neutral-600 focus:outline-none focus:ring-1 focus:ring-[#84cc16]/50 focus:border-[#84cc16] font-mono"
                  />
                  <button
                    onClick={() => (running ? sendGuidance() : startAgentWithContext())}
                    disabled={!guidance.trim()}
                    className="px-3 py-2 bg-[#84cc16]/20 hover:bg-[#84cc16]/30 text-[#84cc16] border border-[#84cc16]/30 rounded-lg text-xs font-medium transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    {running ? "Enviar" : "Reanudar con contexto"}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar - Findings */}
          <div className="h-full min-h-0 overflow-y-auto pr-2 space-y-4">
            {/* Status card */}
            <div className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Estado</h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-neutral-500">Status</span>
                  <span className="text-white capitalize">{status.replace("_", " ")}</span>
                </div>
                {audit?.started_at && (
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Inicio</span>
                    <span className="text-white">
                      {new Date(audit.started_at).toLocaleTimeString("es-ES")}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-neutral-500">Pasos</span>
                  <span className="text-white">{steps.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">Hallazgos</span>
                  <span className="text-[#84cc16] font-semibold">{vulnerabilities.length}</span>
                </div>
              </div>
            </div>

            {/* Open Ports */}
            <div className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Reconocimiento — Puertos abiertos</h3>
              {openPorts.length === 0 ? (
                <p className="text-xs text-neutral-600">Sin puertos detectados aún</p>
              ) : (
                <div className="space-y-2">
                  {openPorts.map((p, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between gap-2 p-2 bg-[#0a0a0a] border border-[#262626] rounded-lg text-xs"
                    >
                      <span className="text-white font-mono">
                        {p.port}/{p.protocol}
                      </span>
                      <span className="text-neutral-400 truncate">
                        {p.service}
                        {p.version ? ` ${p.version}` : ""}
                      </span>
                      <span className="text-[10px] text-[#84cc16] uppercase whitespace-nowrap">{p.state}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Suggested Attacks */}
            <div className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Ataques posibles</h3>
              {attacks.length === 0 ? (
                <p className="text-xs text-neutral-600">Sin sugerencias aún</p>
              ) : (
                <div className="space-y-2">
                  {attacks.map((a, i) => (
                    <div key={i} className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
                      <span className="text-xs font-medium text-white">
                        {a.port} · {a.service}
                      </span>
                      <p className="text-[11px] text-neutral-400 mt-1">
                        → <span className="text-[#84cc16] font-semibold">{a.tool}</span>: {a.reason}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Vulnerabilities */}
            <div className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Vulnerabilidades</h3>
              {vulnerabilities.length === 0 ? (
                <p className="text-xs text-neutral-600">No se han encontrado vulnerabilidades aún</p>
              ) : (
                <div className="space-y-2">
                  {vulnerabilities.map((vuln) => (
                    <div
                      key={vuln.id}
                      className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg"
                    >
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <span className="text-xs font-medium text-white">{vuln.title}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border whitespace-nowrap ${SEVERITY_COLORS[vuln.severity] || SEVERITY_COLORS.info}`}>
                          {vuln.severity}
                        </span>
                      </div>
                      {vuln.cvss_score !== null && (
                        <span className="text-[10px] text-neutral-500">CVSS: {vuln.cvss_score}</span>
                      )}
                      <p className="text-[11px] text-neutral-400 mt-1 line-clamp-2">{vuln.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
