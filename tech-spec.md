# AI-Audit — Especificación Técnica

Plataforma web de auditoría de ciberseguridad autónoma. Un agente de IA orquesta herramientas de pentesting, analiza resultados y genera reportes con remediación.

---

## Stack

| Componente | Tecnología |
|-----------|-----------|
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind CSS + Shadcn/ui |
| Backend | Python 3.11+ con FastAPI |
| Base de datos | PostgreSQL 16 + pgvector |
| ORM | SQLAlchemy (SQLModel) + Alembic (migraciones) |
| Motor IA | Ollama (inferencia local) |
| Modelo LLM | Modelo pre-entrenado cuantizado (Llama 3 8B / Mistral 7B en GGUF Q4_K_M) |
| Embeddings | nomic-embed-text vía Ollama |
| Tiempo real | WebSocket (stream del agente al frontend) |
| Auth | JWT |
| Reportes | PDF/HTML con weasyprint + Jinja2 |
| Contenedores | Docker Compose |

---

## Arquitectura

Hexagonal (Ports & Adapters). El dominio define interfaces (puertos), las implementaciones concretas son adaptadores intercambiables.

**Adaptadores de entrada:** FastAPI (REST), WebSocket (stream)
**Adaptadores de salida:** subprocess (Nmap, Hydra, Sqlmap), SQLAlchemy (PostgreSQL), cliente Ollama (IA)

---

## Modelo de IA

- **No se hace fine-tuning.** Se usa el modelo pre-entrenado tal cual.
- La especialización en ciberseguridad se logra con **prompt engineering** + **RAG** (contexto de CVEs y writeups inyectado desde pgvector).
- El modelo razona y decide qué herramienta ejecutar; el conocimiento técnico específico lo aporta el contexto RAG.
- Algoritmo de agente: **ReAct** (Thought → Action → Observation en bucle).

---

## Base de Datos — 6 Tablas

| Tabla | Propósito |
|-------|----------|
| `users` | Usuarios del sistema (email, password hash, rol) |
| `targets` | Objetivos de auditoría (IP o dominio, estado de autorización) |
| `audits` | Sesiones de auditoría (estado, timestamps, resumen) |
| `audit_logs` | Registro forense inmutable de cada paso del agente (thought/action/observation + comando ejecutado) |
| `vulnerabilities` | Hallazgos: CVE, severidad CVSS, PoC, remediación |
| `knowledge_base` | CVEs y writeups vectorizados con pgvector para búsqueda RAG |

---

## Herramientas de Pentesting

| Herramienta | Función |
|------------|---------|
| Nmap | Escaneo de puertos, servicios y versiones |
| Hydra | Fuerza bruta controlada (SSH, FTP) |
| Sqlmap | Detección de inyección SQL |

Se ejecutan vía `asyncio.subprocess`. Todo comando queda registrado en `audit_logs`.

---

## Endpoints Principales

```
POST   /api/v1/auth/login
POST   /api/v1/auth/register
POST   /api/v1/audits                  # Iniciar auditoría
GET    /api/v1/audits                  # Listar auditorías
GET    /api/v1/audits/{id}             # Detalle
POST   /api/v1/audits/{id}/continue    # Auditor decide: continuar escaneando
POST   /api/v1/audits/{id}/deeper      # Profundizar en hallazgo actual
POST   /api/v1/audits/{id}/skip        # Saltar hallazgo actual
POST   /api/v1/audits/{id}/stop        # Detener auditoría, generar reporte parcial
GET    /api/v1/audits/{id}/findings    # Hallazgos encontrados hasta el momento
WS     /api/v1/audits/{id}/stream      # Stream tiempo real
GET    /api/v1/reports/{audit_id}/pdf  # Descargar reporte
```

---

## Flujo de Ejecución

1. Usuario ingresa IP/dominio y autoriza el escaneo inicial
2. El agente IA inicia el bucle ReAct: analiza → decide herramienta → ejecuta → observa resultado
3. Cada decisión se enriquece con contexto RAG (CVEs relevantes desde pgvector)
4. **Al detectar cualquier hallazgo**, el agente lo muestra en el frontend como card clasificada y **solicita decisión al auditor**:
   - `continue` — seguir escaneando
   - `deeper` — profundizar en este hallazgo (explotar/validar PoC)
   - `skip` — saltar este hallazgo y continuar
   - `stop` — detener la auditoría y generar reporte con todo lo encontrado hasta ahora
5. Todo queda registrado en `audit_logs` (forense inmutable)
6. El auditor puede detener la auditoría **en cualquier momento** y obtener un reporte parcial
7. Al finalizar (por decisión del auditor o por agotamiento de superficie), genera reporte PDF/HTML con hallazgos clasificados por CVSS

---

## Estados del Agente

| Estado | Descripción |
|--------|------------|
| `scanning` | El agente está ejecutando herramientas y analizando resultados |
| `awaiting_decision` | Hallazgo detectado, esperando decisión del auditor |
| `exploiting` | El auditor autorizó profundizar; el agente valida/explota el hallazgo |
| `reporting` | Generando reporte (parcial o final) |
| `idle` | Auditoría finalizada o detenida por el auditor |

---

## Reportes

- **Progresivos:** el frontend muestra hallazgos en cards en tiempo real conforme se descubren, clasificados por severidad CVSS.
- **Parciales:** disponibles en cualquier momento vía `stop`. Contienen todos los hallazgos encontrados hasta ese punto.
- **Final:** generado al completar la auditoría. Incluye resumen ejecutivo, hallazgos con PoC, remediación por hallazgo, y clasificación CVSS.
- **Formato:** PDF y HTML con weasyprint + Jinja2.

---

## Infraestructura

- **Docker Compose** con 4 servicios: frontend, backend, PostgreSQL (pgvector), Ollama
- **Requisitos mínimos:** 16 GB RAM, 6 núcleos CPU, SSD 256 GB, Linux o WSL2
- **Recomendado:** 32 GB RAM, GPU con 8 GB+ VRAM para acelerar inferencia
- Operación 100% local, sin APIs externas
