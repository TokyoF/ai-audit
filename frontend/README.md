# AI-Audit — Frontend

Interfaz web con Next.js para la plataforma de auditoría de ciberseguridad.

## Requisitos

- Node.js 18+
- pnpm (gestor de paquetes)

## Setup

### 1. Instalar dependencias

```bash
cd frontend
pnpm install
```

### 2. Iniciar en desarrollo

```bash
pnpm dev
```

El frontend estará en `http://localhost:3000`.

### 3. Asegurar que el backend esté corriendo

El frontend se conecta al backend en `http://localhost:8000`. Asegúrate de que:
- Docker Compose esté levantado (PostgreSQL + Ollama)
- El backend esté corriendo con `uvicorn`

Ver `backend/README.md` para instrucciones.

## Páginas

| Ruta | Descripción |
|------|-------------|
| `/login` | Login y registro de usuarios |
| `/dashboard` | Lista de auditorías + crear nueva |
| `/dashboard/audit/[id]` | Detalle de auditoría con terminal del agente IA |

## Stack

- **Next.js 16** (App Router)
- **React 19**
- **TypeScript**
- **Tailwind CSS v4**
- **Tema:** Dark cybersecurity con acentos verde neón (#84cc16)

## Estructura

```
frontend/
├── app/
│   ├── layout.tsx              # Layout global (dark theme)
│   ├── page.tsx                # Redirect a /login
│   ├── globals.css             # Variables CSS del tema
│   ├── login/
│   │   └── page.tsx            # Login/Register
│   └── dashboard/
│       ├── page.tsx            # Lista de auditorías
│       └── audit/
│           └── [id]/
│               └── page.tsx    # Terminal del agente + hallazgos
├── package.json
├── tailwind.config.ts
├── tsconfig.json
└── next.config.ts
```

## Notas

- La autenticación usa JWT almacenado en `localStorage`
- El stream del agente usa WebSocket nativo (`ws://localhost:8000/api/v1/audits/{id}/stream`)
- El tema usa colores inline (`#0a0a0a`, `#111111`, `#262626`, `#84cc16`) para consistencia
