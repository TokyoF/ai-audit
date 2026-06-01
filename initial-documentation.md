# Documento de Especificación Técnica: AI-Audit

## 1. Descripción General del Sistema
**AI-Audit** es una plataforma web autónoma de auditoría de ciberseguridad y gestión de vulnerabilidades éticas. El sistema permite a los administradores de TI y auditores introducir un objetivo (dirección IP o dominio) para iniciar un reconocimiento y análisis de seguridad en tiempo real. 

A diferencia de los scripts automáticos tradicionales, **AI-Audit** implementa una arquitectura basada en agentes de Inteligencia Artificial que imita el razonamiento lógico de un Pentester profesional. El sistema analiza el entorno, selecciona y ejecuta herramientas de red de forma asíncrona, valida los hallazgos mediante pruebas de concepto (PoC) controladas y autorizadas, y genera reportes técnicos con guías de remediación inmedatizables.

---

## 2. Lo que Hace la Aplicación (Flujo de Ejecución)

1. **Definición de Objetivo:** El usuario ingresa una IP o dominio en la interfaz web y autoriza formalmente el inicio del escaneo.
2. **Reconocimiento Autónomo Dinámico:** El Agente de IA toma el objetivo e interactúa dinámicamente con la red utilizando herramientas de sistema para descubrir puertos, servicios y versiones de software.
3. **Análisis de Vulnerabilidades (RAG):** El sistema procesa las salidas de texto de la terminal y las contrasta mediante búsqueda híbrida vectorial con una base de datos local de CVEs (Common Vulnerabilities and Exposures) y metodologías de mitigación.
4. **Validación Autorizada (Explotación Controlada):** Si se sospecha de un fallo crítico, la aplicación solicita confirmación explícita al usuario a través de la interfaz web. Con el consentimiento, la IA ejecuta comandos específicos y limitados para obtener una evidencia o Prueba de Concepto (PoC) sin alterar ni extraer información sensible.
5. **Auditoría Forense Inmutable:** Todos los comandos generados por la IA, los parámetros de red y las respuestas obtenidas se registran de forma obligatoria y cronológica en la base de datos relacional.
6. **Reporte y Remediación:** Al concluir el ciclo, la aplicación genera un reporte descargable en PDF o HTML estructurando los fallos por su nivel de criticidad según el estándar CVSS y anexando soluciones o parches listos para ser aplicados.

---

## 3. Patrón de Arquitectura: Arquitectura Hexagonal (Ports & Adapters)

Para asegurar la escalabilidad, mantenibilidad y la total independencia de los frameworks, el Core de la aplicación está diseñado bajo la **Arquitectura Hexagonal**.

* **El Dominio (Core):** Contiene las reglas puras del negocio. Aquí residen el flujo principal del pentesting, el motor de toma de decisiones (Algoritmo ReAct), las métricas de puntuación CVSS y las políticas éticas del Agente.
* **Puertos (Ports):** Interfaces de código que definen los contratos de cómo el dominio se comunica con el exterior (ej. `ScannerPort`, `DatabasePort`, `NotificationPort`).
* **Adaptadores (Adapters):** Implementaciones técnicas específicas que se conectan a los puertos.
    * *Adaptadores de Entrada:* FastAPI para exponer los endpoints de la API, WebSockets para la comunicación reactiva.
    * *Adaptadores de Salida:* Implementación en Python de comandos CLI (`subprocess` para Nmap, Hydra), ORM SQLAlchemy para conectar con PostgreSQL, y el conector de Ollama para la IA.

---

## 4. Stack Tecnológico

La aplicación divide estrictamente las responsabilidades de interfaz, procesamiento de datos e inteligencia artificial en tres capas:

### Frontend
* **Framework:** Next.js (React) con TypeScript.
* **Estilos:** Tailwind CSS.
* **Componentes de UI:** Shadcn/ui o Radix Primitives.
* **Comunicación de Datos:** WebSockets y Server-Sent Events (SSE) para la actualización interactiva en tiempo real del "flujo de pensamiento" del agente sin recargar la página.

### Backend & Core de IA
* **Framework Web:** FastAPI (Python). Elegido por su alto rendimiento asíncrono y soporte nativo para tareas en segundo plano.
* **Orquestación Asíncrona:** Python `asyncio` y ejecuciones mediante el módulo `subprocess` para el control seguro de herramientas del sistema operativo.
* **ORM / Acceso a Datos:** SQLAlchemy (usando SQLModel) para operaciones asíncronas con la base de datos.

### Base de Datos y Persistencia
* **Base de Datos Relacional:** PostgreSQL. Gestiona usuarios, objetivos, auditorías forenses, credenciales cifradas e historial de reportes.
* **Motor Vectorial:** Extensión `pgvector` incorporada en PostgreSQL para el almacenamiento de los embeddings de los CVEs y Writeups históricos, permitiendo búsquedas semánticas rápidas durante la fase RAG.

---

## 5. Modelos e Inteligencia Artificial

### El Cerebro (Modelo Especializado)
El sistema no depende de llamadas a APIs externas en la nube. Utiliza un Modelo de Lenguaje de Gran Escala (LLM) de código abierto (como **Llama 3 8B** o **Mistral 7B**) ejecutado localmente mediante **Ollama**.

* **Optimización de Recursos:** Para operar de forma eficiente en hardware estándar, se utiliza un modelo pre-entrenado y cuantizado en formato **GGUF a 4 bits**. Este componente encapsula el conocimiento consolidado equivalente a un Fine-Tuning masivo en el dominio de ciberseguridad, reconociendo estructuras de red, logs y taxonomías de exploits.

### Algoritmo de Razonamiento: ReAct (Reasoning + Acting)
Para gobernar las decisiones del agente en tiempo real, se implementa el algoritmo **ReAct** a través de librerías como LangChain. El motor de IA opera en un bucle iterativo:

1. **Thought (Pensamiento):** El modelo analiza los datos actuales de la auditoría (ej: *"El servicio expuesto en el puerto 21 permite acceso anónimo"*).
2. **Action (Acción):** La IA decide qué herramienta o comando invocar de forma específica (ej: *"Voy a listar el directorio raíz usando el comando FTP nativo"*).
3. **Observation (Observación):** El core ejecuta la acción en la consola de Linux, captura el resultado de la terminal y se lo devuelve a la IA para que reinicie el bucle o concluya el hallazgo.

---

## 6. Herramientas de Seguridad Integradas
El entorno del sistema operativo (o contenedor Docker) aloja las herramientas nativas que el backend de Python orquesta:
* **Nmap:** Escaneo de puertos, descubrimiento de topología de red y detección de versiones de servicios.
* **Hydra:** Pruebas controladas de fuerza bruta sobre diccionarios acotados si se detectan servicios de autenticación débiles (SSH, FTP).
* **Sqlmap:** Detección automática y validación de parámetros vulnerables a inyección SQL en aplicaciones web expuestas.

---

## 7. Infraestructura y Requisitos del Sistema (Entorno Local)

Al utilizar modelos cuantizados avanzados, los requisitos de cómputo se optimizan para entornos locales accesibles:

* **Procesador (CPU):** Intel Core i7/i9 (Generación 12+) o AMD Ryzen 7/9 (Serie 5000+), mínimo de 6 a 8 núcleos físicos para la gestión paralela de procesos de red y compilación de Next.js.
* **Memoria RAM:** Mínimo 16 GB, recomendado **32 GB de RAM** para soportar de manera simultánea PostgreSQL, Ollama, Next.js y las herramientas de consola.
* **Almacenamiento:** Unidad de estado sólido **SSD NVMe M.2** con al menos 500 GB de espacio libre para lecturas e indexaciones vectoriales veloces.
* **Sistema Operativo:** Entorno Linux nativo (Ubuntu, Debian, Parrot OS) o Windows configurado rigurosamente mediante **WSL2** (Windows Subsystem for Linux) para garantizar la compatibilidad de permisos de sockets y comandos de red.