"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { API_URL } from "@/lib/api";

interface Audit {
  id: string;
  target_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  summary: string | null;
  created_by?: string;
  created_at: string;
  host?: string | null;
  vuln_count?: number;
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  pending: { label: "Pendiente", color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  scanning: { label: "Escaneando", color: "bg-[#84cc16]/20 text-[#84cc16] border-[#84cc16]/30" },
  awaiting_decision: { label: "Esperando", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  exploiting: { label: "Explotando", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  reporting: { label: "Reportando", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  completed: { label: "Finalizada", color: "bg-green-500/20 text-green-400 border-green-500/30" },
  idle: { label: "Finalizada", color: "bg-neutral-500/20 text-neutral-400 border-neutral-500/30" },
};

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: "pending", label: "Pendiente" },
  { value: "scanning", label: "Escaneando" },
  { value: "completed", label: "Finalizada" },
];

export default function DashboardPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [host, setHost] = useState("");
  const [description, setDescription] = useState("");
  const [creating, setCreating] = useState(false);
  const router = useRouter();

  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }
    fetchAudits();
  }, []);

  const fetchAudits = async () => {
    try {
      const res = await fetch(`${API_URL}/audits`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) {
        localStorage.removeItem("token");
        router.push("/login");
        return;
      }
      const data = await res.json();
      setAudits(data);
    } catch {
      console.error("Error fetching audits");
    } finally {
      setLoading(false);
    }
  };

  const createAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      const res = await fetch(`${API_URL}/audits`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ host, description: description || null }),
      });
      if (res.ok) {
        setHost("");
        setDescription("");
        setShowModal(false);
        fetchAudits();
      }
    } catch {
      console.error("Error creating audit");
    } finally {
      setCreating(false);
    }
  };

  const deleteAudit = async (id: string) => {
    if (!window.confirm("¿Eliminar esta auditoría y todos sus datos? Esta acción no se puede deshacer.")) {
      return;
    }
    try {
      const res = await fetch(`${API_URL}/audits/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok || res.status === 204) {
        setAudits((prev) => prev.filter((a) => a.id !== id));
      }
    } catch {
      console.error("Error deleting audit");
    }
  };

  const setAuditStatus = async (id: string, status: string) => {
    try {
      const res = await fetch(`${API_URL}/audits/${id}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status }),
      });
      if (res.ok) {
        const updated = await res.json();
        setAudits((prev) => prev.map((a) => (a.id === id ? { ...a, ...updated } : a)));
      }
    } catch {
      console.error("Error updating audit status");
    }
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleString("es-ES", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] relative">
      {/* Background effects */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[#84cc16]/3 rounded-full blur-[150px]" />
      <div className="absolute bottom-0 left-0 w-[400px] h-[300px] bg-[#84cc16]/5 rounded-full blur-[120px]" />

      {/* Navbar */}
      <nav className="relative z-10 border-b border-[#262626] bg-[#0a0a0a]/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#84cc16] flex items-center justify-center">
              <svg className="w-5 h-5 text-[#0a0a0a]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="text-lg font-bold text-white">AI-Audit</span>
          </div>
          <button
            onClick={() => {
              localStorage.removeItem("token");
              router.push("/login");
            }}
            className="text-sm text-neutral-500 hover:text-white transition-colors"
          >
            Cerrar sesión
          </button>
        </div>
      </nav>

      {/* Content */}
      <main className="relative z-10 max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-sm text-neutral-500 mt-1">Gestiona tus auditorías de seguridad</p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2.5 bg-[#84cc16] hover:bg-[#a3e635] text-[#0a0a0a] font-semibold rounded-lg transition-all duration-200 flex items-center gap-2 text-sm"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
            </svg>
            Nueva auditoría
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: "Total", value: audits.length, icon: "M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" },
            { label: "Activas", value: audits.filter(a => a.status === "scanning" || a.status === "exploiting").length, icon: "M5.636 5.636a9 9 0 1012.728 0M12 3v9" },
            { label: "Pendientes", value: audits.filter(a => a.status === "awaiting_decision").length, icon: "M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" },
            { label: "Finalizadas", value: audits.filter(a => a.status === "idle").length, icon: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" },
          ].map((stat) => (
            <div key={stat.label} className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#84cc16]/10 flex items-center justify-center">
                  <svg className="w-5 h-5 text-[#84cc16]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={stat.icon} />
                  </svg>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{stat.value}</p>
                  <p className="text-xs text-neutral-500">{stat.label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Audits list */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <svg className="animate-spin h-8 w-8 text-[#84cc16]" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          </div>
        ) : audits.length === 0 ? (
          <div className="text-center py-20 bg-[#111111]/50 border border-[#262626] rounded-2xl">
            <div className="w-16 h-16 rounded-2xl bg-[#84cc16]/10 flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-[#84cc16]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-white mb-1">No hay auditorías</h3>
            <p className="text-sm text-neutral-500 mb-6">Crea tu primera auditoría para comenzar</p>
            <button
              onClick={() => setShowModal(true)}
              className="px-5 py-2.5 bg-[#84cc16] hover:bg-[#a3e635] text-[#0a0a0a] font-semibold rounded-lg transition-all duration-200 text-sm"
            >
              Nueva auditoría
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {audits.map((audit) => {
              const statusInfo = STATUS_LABELS[audit.status] || { label: audit.status, color: "bg-neutral-500/20 text-neutral-400 border-neutral-500/30" };
              return (
                <div
                  key={audit.id}
                  onClick={() => router.push(`/dashboard/audit/${audit.id}`)}
                  className="bg-[#111111]/80 border border-[#262626] rounded-xl p-5 cursor-pointer hover:border-[#84cc16]/30 hover:bg-[#111111] transition-all duration-200 group"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-[#84cc16]/10 flex items-center justify-center group-hover:bg-[#84cc16]/20 transition-colors">
                        <svg className="w-5 h-5 text-[#84cc16]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-white font-medium">{audit.host || "Auditoría"}</p>
                        <p className="text-xs text-neutral-500 font-mono">{audit.id.slice(0, 8)}...</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs px-2.5 py-1 rounded-full border bg-[#1a1a1a] text-neutral-400 border-[#262626]">
                        {audit.vuln_count ?? 0} hallazgos
                      </span>
                      <span className={`text-xs px-3 py-1 rounded-full border ${statusInfo.color}`}>
                        {statusInfo.label}
                      </span>
                      <select
                        value={audit.status}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => {
                          e.stopPropagation();
                          setAuditStatus(audit.id, e.target.value);
                        }}
                        className="text-xs px-2 py-1 bg-[#1a1a1a] border border-[#262626] rounded-lg text-neutral-300 focus:outline-none focus:ring-1 focus:ring-[#84cc16]/50"
                      >
                        {STATUS_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                      <span className="text-xs text-neutral-600">{formatDate(audit.created_at)}</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteAudit(audit.id);
                        }}
                        className="p-1.5 rounded-lg text-red-400/70 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Eliminar auditoría"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                        </svg>
                      </button>
                      <svg className="w-4 h-4 text-neutral-600 group-hover:text-[#84cc16] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                      </svg>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* Modal crear auditoría */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowModal(false)} />
          <div className="relative bg-[#111111] border border-[#262626] rounded-2xl p-8 w-full max-w-md mx-4 shadow-2xl">
            <h2 className="text-xl font-semibold text-white mb-1">Nueva auditoría</h2>
            <p className="text-sm text-neutral-500 mb-6">Ingresa el objetivo a escanear</p>

            <form onSubmit={createAudit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-neutral-400 mb-1.5">
                  Host / IP / Dominio
                </label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  required
                  className="w-full px-4 py-2.5 bg-[#0a0a0a] border border-[#262626] rounded-lg text-white placeholder-neutral-600 focus:outline-none focus:ring-2 focus:ring-[#84cc16]/50 focus:border-[#84cc16] transition-all font-mono"
                  placeholder="192.168.1.1 o ejemplo.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-neutral-400 mb-1.5">
                  Descripción <span className="text-neutral-600">(opcional)</span>
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                  className="w-full px-4 py-2.5 bg-[#0a0a0a] border border-[#262626] rounded-lg text-white placeholder-neutral-600 focus:outline-none focus:ring-2 focus:ring-[#84cc16]/50 focus:border-[#84cc16] transition-all resize-none"
                  placeholder="Servidor web de producción..."
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-2.5 bg-[#1a1a1a] hover:bg-[#262626] text-neutral-400 font-medium rounded-lg transition-all duration-200 text-sm border border-[#262626]"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="flex-1 py-2.5 bg-[#84cc16] hover:bg-[#a3e635] text-[#0a0a0a] font-semibold rounded-lg transition-all duration-200 disabled:opacity-50 text-sm flex items-center justify-center gap-2"
                >
                  {creating ? (
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9" />
                    </svg>
                  )}
                  {creating ? "Creando..." : "Iniciar escaneo"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
