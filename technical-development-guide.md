# Guía de Desarrollo Técnico: AI-Audit

## 1. Visión General de la Arquitectura

AI-Audit se compone de tres capas principales desplegadas como servicios independientes:

| Capa | Tecnología | Puerto | Responsabilidad |
|------|-----------|--------|----------------|
| Frontend | Next.js 14 (App Router) + TypeScript | 3000 | Interfaz de usuario, visualización en tiempo real |
| Backend | FastAPI (Python 3.11+) | 8000 | API REST, WebSockets, orquestación del agente IA |
| Base de Datos | PostgreSQL 16 + pgvector | 5432 | Persistencia relacional + búsqueda vectorial |
| Motor IA | Ollama | 11434 | Servicio local de inferencia LLM |

### Patrón Arquitectónico: Hexagonal (Ports & Adapters)

```
                    ┌─────────────────────────────────┐
                    │          DOMINIO (Core)          │
                    │                                  │
  Adaptadores      │  - Motor ReAct (bucle de agente) │      Adaptadores
  de Entrada       │  - Políticas éticas              │      de Salida
                   │  - Scoring CVSS                  │
  ┌──────────┐     │  - Flujo de auditoría            │     ┌──────────────┐
  │ FastAPI   │◄──►│                                  │◄──► │ subprocess   │
  │ (REST)    │    │     PUERTOS (Interfaces)         │     │ (Nmap, Hydra,│
  ├──────────┤     │                                  │     │  Sqlmap)     │
  │ WebSocket │◄──►│  ScannerPort                     │◄──► ├──────────────┤
  │ (SSE)     │    │  DatabasePort                    │     │ SQLAlchemy   │
  └──────────┘     │  AIModelPort                     │     │ (PostgreSQL) │
                   │  NotificationPort                │     ├──────────────┤
                   │                                  │     │ Ollama Client│
                   └─────────────────────────────────┘     └──────────────┘
```

---

## 2. Frontend — Next.js

### Estructura de Directorios

```
frontend/
├── src/
│   ├── app/                    # App Router (rutas)
│   │   ├── (auth)/             # Rutas de autenticación
│   │   │   ├── login/
│   │   │   └── register/
│   │   ├── dashboard/          # Panel principal
│   │   ├── audit/
│   │   │   ├── [id]/           # Detalle de auditoría en tiempo real
│   │   │   └── new/            # Crear nueva auditoría
│   │   ├── reports/            # Historial de reportes
│   │   └── layout.tsx
│   ├── components/
│   │   ├── ui/                 # Componentes Shadcn/ui
│   │   ├── audit/              # Componentes específicos de auditoría
│   │   │   ├── TerminalStream.tsx    # Stream en vivo del agente
│   │   │   ├── ThoughtProcess.tsx    # Visualización ReAct
│   │   │   └── VulnerabilityCard.tsx
│   │   └── layout/
│   ├── hooks/
│   │   ├── useWebSocket.ts     # Conexión WebSocket al backend
│   │   ├── useAuditStream.ts   # Hook para stream de auditoría
│   │   └── useAuth.ts
│   ├── lib/
│   │   ├── api.ts              # Cliente HTTP (fetch/axios)
│   │   └── utils.ts
│   └── types/
│       ├── audit.ts
│       └── vulnerability.ts
├── tailwind.config.ts
├── next.config.ts
└── package.json
```

### Comunicación en Tiempo Real

El frontend se conecta al backend mediante **WebSocket** para recibir el flujo de pensamiento del agente:

```typescript
// hooks/useAuditStream.ts
type AgentEvent = {
  type: 'thought' | 'action' | 'observation' | 'result' | 'error';
  timestamp: string;
  content: string;
  metadata?: Record<string, unknown>;
};
```

Cada evento del bucle ReAct (Thought → Action → Observation) se renderiza progresivamente en `ThoughtProcess.tsx`, dando visibilidad total al usuario sobre qué está haciendo el agente y por qué.

### Dependencias Principales

- `next` 14.x, `react` 18.x, `typescript` 5.x
- `tailwindcss` + `shadcn/ui` (componentes)
- `socket.io-client` o WebSocket nativo para streams
- `react-query` / `swr` para caché y fetching de datos REST
- `zustand` para estado global ligero

---

## 3. Backend — FastAPI (Python)

### Estructura de Directorios (Hexagonal)

```
backend/
├── src/
│   ├── domain/                     # CORE — sin dependencias externas
│   │   ├── models/
│   │   │   ├── audit.py            # Entidad Auditoría
│   │   │   ├── vulnerability.py    # Entidad Vulnerabilidad
│   │   │   ├── target.py           # Entidad Objetivo (IP/dominio)
│   │   │   └── finding.py          # Hallazgo individual
│   │   ├── services/
│   │   │   ├── audit_service.py    # Lógica de orquestación de auditoría
│   │   │   ├── scoring_service.py  # Cálculo CVSS
│   │   │   └── ethics_policy.py    # Validaciones éticas y límites
│   │   └── ports/                  # Interfaces (ABC)
│   │       ├── scanner_port.py     # Puerto: ejecución de herramientas
│   │       ├── database_port.py    # Puerto: persistencia
│   │       ├── ai_model_port.py    # Puerto: inferencia LLM
│   │       └── notification_port.py
│   │
│   ├── adapters/                   # Implementaciones concretas
│   │   ├── inbound/                # Adaptadores de entrada
│   │   │   ├── api/
│   │   │   │   ├── routes/
│   │   │   │   │   ├── audit_routes.py
│   │   │   │   │   ├── auth_routes.py
│   │   │   │   │   └── report_routes.py
│   │   │   │   ├── websocket/
│   │   │   │   │   └── audit_ws.py     # WebSocket handler
│   │   │   │   ├── dependencies.py
│   │   │   │   └── middleware.py
│   │   │   └── schemas/                # Pydantic request/response
│   │   │       ├── audit_schema.py
│   │   │       └── auth_schema.py
│   │   │
│   │   └── outbound/              # Adaptadores de salida
│   │       ├── tools/
│   │       │   ├── nmap_adapter.py
│   │       │   ├── hydra_adapter.py
│   │       │   └── sqlmap_adapter.py
│   │       ├── persistence/
│   │       │   ├── sqlalchemy_adapter.py
│   │       │   ├── models_orm.py       # Modelos SQLAlchemy/SQLModel
│   │       │   └── migrations/         # Alembic
│   │       ├── ai/
│   │       │   ├── ollama_adapter.py   # Cliente Ollama
│   │       │   └── rag_engine.py       # Búsqueda vectorial + contexto
│   │       └── reporting/
│   │           └── pdf_generator.py
│   │
│   ├── agent/                     # Motor del Agente IA
│   │   ├── react_engine.py        # Bucle ReAct principal
│   │   ├── tool_registry.py       # Registro de herramientas disponibles
│   │   ├── prompt_templates.py    # System prompts y templates
│   │   └── memory.py              # Contexto conversacional del agente
│   │
│   └── config/
│       ├── settings.py            # Variables de entorno (Pydantic Settings)
│       └── database.py            # Configuración async de PostgreSQL
│
├── main.py                        # Punto de entrada FastAPI
├── alembic.ini
├── requirements.txt
└── Dockerfile
```

### Endpoints Principales

```
POST   /api/v1/auth/login              # Autenticación JWT
POST   /api/v1/auth/register           # Registro de usuario

POST   /api/v1/audits                  # Iniciar nueva auditoría
GET    /api/v1/audits                  # Listar auditorías del usuario
GET    /api/v1/audits/{id}             # Detalle de auditoría
POST   /api/v1/audits/{id}/authorize   # Autorizar explotación controlada
WS     /api/v1/audits/{id}/stream      # WebSocket: stream en tiempo real

GET    /api/v1/reports/{audit_id}      # Obtener reporte generado
GET    /api/v1/reports/{audit_id}/pdf  # Descargar reporte PDF
```

### Ejecución de Herramientas (subprocess)

Cada herramienta de seguridad se ejecuta de forma asíncrona y aislada:

```python
# adapters/outbound/tools/nmap_adapter.py (ejemplo conceptual)
class NmapAdapter(ScannerPort):
    async def scan(self, target: str, options: list[str]) -> ScanResult:
        cmd = ["nmap", *options, target]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        # Parsear salida y devolver modelo de dominio
        return self._parse_output(stdout.decode())
```

Cada comando ejecutado y su salida se registran obligatoriamente en la tabla `audit_logs` (auditoría forense inmutable).

---

## 4. Inteligencia Artificial — Modelo Pre-entrenado

### Enfoque: Modelo Pre-entrenado + Prompt Engineering + RAG

**No se realizará fine-tuning ni pre-entrenamiento** del modelo. En su lugar, se utilizará un LLM de código abierto pre-entrenado tal cual, potenciado mediante:

1. **Prompt Engineering especializado:** System prompts detallados que contextualizan al modelo como pentester experto, definiendo su rol, limitaciones éticas, formato de respuesta y herramientas disponibles.
2. **RAG (Retrieval-Augmented Generation):** Antes de cada decisión, el agente consulta la base vectorial de CVEs y writeups para inyectar contexto técnico relevante al prompt, compensando las limitaciones del modelo base.
3. **Herramientas estructuradas (Tool Calling):** El modelo no necesita "saber" ciberseguridad a fondo — necesita saber cuándo y cómo invocar Nmap, Hydra o Sqlmap, e interpretar sus salidas con ayuda del contexto RAG.

### Modelo Seleccionado

| Aspecto | Especificación |
|---------|---------------|
| Modelo base | Llama 3 8B o Mistral 7B (evaluar rendimiento) |
| Formato | GGUF cuantizado a 4 bits (Q4_K_M) |
| Runtime | Ollama (servicio local, API REST en puerto 11434) |
| RAM estimada | ~6-8 GB para el modelo cargado |
| Fine-tuning | **No aplica** — se compensa con prompt engineering + RAG |

### Flujo RAG (Retrieval-Augmented Generation)

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Salida de    │────►│ Generar embedding │────►│ Búsqueda en  │
│ herramienta  │     │ del contexto      │     │ pgvector     │
│ (ej: Nmap)   │     │                   │     │ (CVEs,       │
└──────────────┘     └──────────────────┘     │  writeups)   │
                                               └──────┬───────┘
                                                      │
                                                      ▼
                     ┌──────────────────┐     ┌──────────────┐
                     │ LLM genera       │◄────│ Prompt =     │
                     │ decisión/análisis│     │ System +     │
                     │                  │     │ RAG context + │
                     └──────────────────┘     │ Tool output  │
                                               └──────────────┘
```

### Embeddings

Para la generación de embeddings (vectorización de CVEs y consultas) se utiliza un modelo de embeddings ligero también servido por Ollama (ej: `nomic-embed-text` o `all-minilm`), evitando dependencias externas.

### Bucle ReAct del Agente

```python
# agent/react_engine.py (flujo conceptual)
async def react_loop(target: str, context: AuditContext):
    while not context.is_complete:
        # 1. THOUGHT — el LLM analiza el estado actual
        thought = await llm.generate(
            system_prompt=PENTESTER_SYSTEM_PROMPT,
            context=context.history + rag_context
        )

        # 2. ACTION — parsear la herramienta y parámetros que decidió usar
        action = parse_tool_call(thought)

        if action.requires_authorization:
            await notify_user_and_wait(action)  # WebSocket → frontend

        # 3. OBSERVATION — ejecutar la herramienta y capturar resultado
        observation = await tool_registry.execute(action)

        # Registrar todo en audit_log (forense inmutable)
        await audit_log.record(thought, action, observation)

        # Alimentar al contexto para la siguiente iteración
        context.append(thought, action, observation)
```

---

## 5. Base de Datos — PostgreSQL + pgvector

### Esquema Principal

```sql
-- Usuarios y autenticación
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'auditor',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Objetivos de auditoría
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    address VARCHAR(255) NOT NULL,         -- IP o dominio
    target_type VARCHAR(20) NOT NULL,      -- 'ip' | 'domain'
    authorized BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Auditorías
CREATE TABLE audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id),
    status VARCHAR(30) DEFAULT 'pending',  -- pending | running | completed | failed
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    summary JSONB                           -- Resumen general de hallazgos
);

-- Log forense inmutable (cada acción del agente)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    audit_id UUID REFERENCES audits(id),
    step_type VARCHAR(20) NOT NULL,        -- 'thought' | 'action' | 'observation'
    content TEXT NOT NULL,
    command_executed TEXT,                   -- Comando exacto si aplica
    tool_name VARCHAR(50),
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerabilidades encontradas
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audits(id),
    cve_id VARCHAR(30),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,         -- critical | high | medium | low | info
    cvss_score DECIMAL(3,1),
    proof_of_concept TEXT,
    remediation TEXT,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Base de conocimiento vectorial (CVEs + writeups)
CREATE TABLE knowledge_base (
    id BIGSERIAL PRIMARY KEY,
    source_type VARCHAR(30) NOT NULL,      -- 'cve' | 'writeup' | 'methodology'
    source_id VARCHAR(50),                 -- ej: CVE-2024-XXXX
    title VARCHAR(500),
    content TEXT NOT NULL,
    embedding vector(768),                 -- pgvector (dimensión según modelo)
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_knowledge_embedding ON knowledge_base
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

### Migraciones

Se utiliza **Alembic** para gestionar migraciones de esquema de forma versionada.

---

## 6. Herramientas de Seguridad

Cada herramienta implementa el puerto `ScannerPort` y se ejecuta como proceso aislado:

| Herramienta | Uso | Adaptador |
|-------------|-----|-----------|
| **Nmap** | Escaneo de puertos, servicios, versiones, OS fingerprinting | `nmap_adapter.py` |
| **Hydra** | Fuerza bruta controlada sobre servicios de autenticación débiles (SSH, FTP) | `hydra_adapter.py` |
| **Sqlmap** | Detección y validación de inyección SQL en endpoints web | `sqlmap_adapter.py` |

Todas las ejecuciones requieren que el objetivo esté marcado como `authorized = TRUE` en la base de datos. Los comandos y parámetros exactos quedan registrados en `audit_logs`.

---

## 7. Generación de Reportes

Al concluir la auditoría, el sistema genera un reporte estructurado:

- **Formato:** PDF y HTML
- **Estructura:** Clasificación de vulnerabilidades por severidad CVSS (Critical → Info)
- **Contenido por hallazgo:** Título, CVE asociado, descripción, evidencia/PoC, impacto estimado, pasos de remediación
- **Librería:** `weasyprint` o `reportlab` para generación de PDF desde templates HTML/Jinja2

---

## 8. Infraestructura y Despliegue Local

### Docker Compose (desarrollo)

```yaml
services:
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    depends_on: [backend]

  backend:
    build: ./backend
    ports: ["8000:8000"]
    depends_on: [db, ollama]
    volumes:
      - ./backend/src:/app/src

  db:
    image: pgvector/pgvector:pg16
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: ai_audit
      POSTGRES_USER: audit_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  ollama:
    image: ollama/ollama
    ports: ["11434:11434"]
    volumes:
      - ollama_models:/root/.ollama
    deploy:
      resources:
        reservations:
          memory: 8G

volumes:
  pgdata:
  ollama_models:
```

### Variables de Entorno (.env)

```
DATABASE_URL=postgresql+asyncpg://audit_user:password@db:5432/ai_audit
OLLAMA_BASE_URL=http://ollama:11434
LLM_MODEL=llama3:8b-instruct-q4_K_M
EMBEDDING_MODEL=nomic-embed-text
JWT_SECRET=<generar-clave-segura>
ALLOWED_ORIGINS=http://localhost:3000
```

### Requisitos Mínimos del Sistema

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| CPU | 6 núcleos | 8+ núcleos |
| RAM | 16 GB | 32 GB |
| Almacenamiento | 256 GB SSD | 500 GB NVMe |
| GPU | No requerida (CPU inference) | NVIDIA con 8GB+ VRAM (acelera inferencia) |
| SO | Ubuntu 22.04 / WSL2 | Linux nativo |

---

## 9. Decisiones Técnicas Clave

1. **Modelo pre-entrenado sin fine-tuning:** No se cuenta con los recursos computacionales (GPU de alto rendimiento, datasets etiquetados, tiempo de entrenamiento) para realizar fine-tuning. La estrategia de prompt engineering + RAG con base de CVEs compensa eficazmente esta limitación, ya que el modelo solo necesita razonar y orquestar — el conocimiento específico lo provee el contexto inyectado.

2. **Ollama como runtime local:** Elimina dependencias de APIs externas (OpenAI, Anthropic), garantiza privacidad total de los datos de auditoría y permite operación offline.

3. **pgvector integrado en PostgreSQL:** Evita la complejidad de mantener un motor vectorial separado (Pinecone, Weaviate). Una sola base de datos para datos relacionales y vectoriales.

4. **Arquitectura Hexagonal:** Permite intercambiar cualquier componente (modelo IA, herramientas, base de datos) sin tocar la lógica de negocio. Si en el futuro se puede hacer fine-tuning, solo se cambia el adaptador de IA.

5. **Auditoría forense obligatoria:** Cada interacción del agente con el sistema queda registrada. Esto es un requisito ético y legal para herramientas de pentesting.
