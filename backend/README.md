# AI-Audit — Backend

API REST + WebSocket con FastAPI para la plataforma de auditoría de ciberseguridad.

## Requisitos

- Python 3.11+
- PostgreSQL 16 con extensión pgvector (vía Docker)
- Ollama corriendo localmente (vía Docker)

## Setup

### 1. Levantar servicios (PostgreSQL + Ollama)

Desde la raíz del proyecto:

```bash
docker-compose up -d
```

Esto levanta:
- PostgreSQL + pgvector en `localhost:5432`
- Ollama en `localhost:11434`

### 2. Crear entorno virtual

```bash
cd backend
python -m venv .venv
```

Activar:
- **Windows (PowerShell):** `.\.venv\Scripts\Activate.ps1`
- **Linux/Mac:** `source .venv/bin/activate`

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

Copiar el archivo de ejemplo desde la raíz:

```bash
cp ../.env.example ../.env
```

Variables principales:
- `DATABASE_URL` — conexión a PostgreSQL (default: `postgresql+asyncpg://aiaudit:aiaudit@localhost:5432/aiaudit`)
- `OLLAMA_BASE_URL` — URL de Ollama (default: `http://localhost:11434`)
- `JWT_SECRET_KEY` — cambiar en producción

### 5. Ejecutar migraciones (Alembic)

```bash
alembic upgrade head
```

Si necesitas regenerar las migraciones desde cero:

```bash
# Limpiar la DB
docker exec -it aiaudit-postgres psql -U aiaudit -d aiaudit -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Borrar migraciones anteriores (conservar __init__.py)
# Regenerar
alembic revision --autogenerate -m "initial_tables"
alembic upgrade head
```

### 6. Descargar modelo LLM en Ollama

```bash
docker exec -it aiaudit-ollama ollama pull llama3:8b
```

### 7. Iniciar el servidor

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

El servidor estará en `http://localhost:8000`.

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | Registrar usuario |
| POST | `/api/v1/auth/login` | Login (devuelve JWT) |
| POST | `/api/v1/audits` | Crear auditoría |
| GET | `/api/v1/audits` | Listar auditorías |
| GET | `/api/v1/audits/{id}` | Detalle de auditoría |
| POST | `/api/v1/audits/{id}/continue` | Continuar escaneando |
| POST | `/api/v1/audits/{id}/deeper` | Profundizar hallazgo |
| POST | `/api/v1/audits/{id}/skip` | Saltar hallazgo |
| POST | `/api/v1/audits/{id}/stop` | Detener auditoría |
| GET | `/api/v1/audits/{id}/findings` | Ver hallazgos |
| WS | `/api/v1/audits/{id}/stream` | Stream del agente en tiempo real |
| GET | `/health` | Health check |

## Estructura

```
backend/
├── app/
│   ├── main.py                  # FastAPI app
│   ├── core/
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── security.py          # JWT + bcrypt
│   │   └── dependencies.py      # Auth dependency
│   ├── domain/
│   │   ├── models/              # SQLModel (6 tablas)
│   │   ├── schemas/             # Pydantic DTOs
│   │   ├── ports/               # Interfaces (pendiente)
│   │   └── agent/               # Agente ReAct
│   ├── adapters/
│   │   ├── db/                  # AsyncSession + repos
│   │   ├── ai/                  # Cliente Ollama
│   │   └── tools/               # Nmap, Hydra, Sqlmap
│   └── api/v1/                  # Routers
├── alembic/                     # Migraciones
├── requirements.txt
└── Dockerfile
```

## Notas

- El backend usa `bcrypt>=4.2.0` directamente (no passlib) por compatibilidad con Python 3.13
- Las migraciones de Alembic requieren el import de `pgvector` — el template `script.py.mako` ya lo incluye
- Para desarrollo local, el backend se corre fuera de Docker; solo PostgreSQL y Ollama corren en contenedores
