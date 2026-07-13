const RAW_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

// REST base, e.g. https://host/api/v1
export const API_URL = `${RAW_BASE}/api/v1`;

// WebSocket base: http->ws, https->wss, e.g. wss://host/api/v1
export const WS_URL = `${RAW_BASE.replace(/^http/, "ws")}/api/v1`;
