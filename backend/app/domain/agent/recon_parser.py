"""Parses AuditLog tool output (nmap/masscan) to surface open ports and
suggest likely attack vectors, without requiring any DB schema changes.
"""

import re
from typing import Any, Iterable

# service/port -> suggested attack tool + reason
_ATTACK_MAP = {
    "ftp": ("ftp_anon", "Servicio FTP expuesto: probar acceso anónimo sin credenciales (y fuerza bruta con hydra)"),
    "ssh": ("hydra", "SSH expuesto: probar fuerza bruta de credenciales"),
    "telnet": ("hydra", "Telnet en texto plano: credenciales y fuerza bruta"),
    "smtp": ("nmap", "SMTP: enumerar usuarios y relay abierto"),
    "http": ("nikto", "Servicio web: escanear con nikto/whatweb/nuclei y buscar SQLi con sqlmap"),
    "https": ("nuclei", "Web TLS: nuclei para CVEs, sslscan para cifrados débiles"),
    "http-proxy": ("nikto", "Proxy web: escanear con nikto"),
    "microsoft-ds": ("enum4linux", "SMB expuesto: enumerar shares y usuarios con enum4linux"),
    "netbios-ssn": ("enum4linux", "NetBIOS/SMB: enumerar con enum4linux"),
    "mysql": ("sqlmap", "Base de datos MySQL: probar credenciales por defecto e inyección"),
    "postgresql": ("hydra", "PostgreSQL expuesto: probar credenciales"),
    "rdp": ("hydra", "RDP expuesto: fuerza bruta de credenciales"),
    "vnc": ("hydra", "VNC expuesto: fuerza bruta"),
    "dns": ("dnsrecon", "DNS: enumeración de subdominios y zonas"),
}

# port-number fallback when the service name is unknown
_PORT_ATTACK = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-proxy",
}

_NMAP_RE = re.compile(
    r"^\s*(\d{1,5})/(tcp|udp)\s+(open|filtered|open\|filtered)\s+([\w\-/?]+)?\s*(.*)$",
    re.IGNORECASE,
)
_MASSCAN_RE = re.compile(r"Discovered open port (\d{1,5})/(tcp|udp)", re.IGNORECASE)


def parse_open_ports(logs: Iterable[Any]) -> list[dict]:
    """Parses nmap grepable/normal lines (e.g. '22/tcp open ssh OpenSSH 8.9p1')
    and masscan lines (e.g. 'Discovered open port 80/tcp on 1.2.3.4') found in
    the `content` field of AuditLog rows. Dedupe by (port, protocol).
    """
    seen: dict[tuple[int, str], dict] = {}
    for log in logs:
        content = getattr(log, "content", "") or ""
        for line in content.splitlines():
            m = _NMAP_RE.match(line)
            if m:
                port = int(m.group(1))
                proto = m.group(2).lower()
                state = m.group(3).lower()
                service = (m.group(4) or "").strip() or "unknown"
                version = (m.group(5) or "").strip() or None
                seen[(port, proto)] = {
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "version": version,
                }
                continue

            mm = _MASSCAN_RE.search(line)
            if mm:
                port = int(mm.group(1))
                proto = mm.group(2).lower()
                key = (port, proto)
                if key not in seen:
                    svc = _PORT_ATTACK.get(port, "unknown")
                    seen[key] = {
                        "port": port,
                        "protocol": proto,
                        "state": "open",
                        "service": svc,
                        "version": None,
                    }

    return sorted(seen.values(), key=lambda p: p["port"])


def suggest_attacks(open_ports: list[dict]) -> list[dict]:
    """Returns list[dict] {port, service, tool, reason} derived from open ports."""
    out = []
    for p in open_ports:
        svc = (p.get("service") or "").lower()
        key = None
        for k in _ATTACK_MAP:
            if k in svc:
                key = k
                break
        if key is None:
            guessed = _PORT_ATTACK.get(p["port"])
            if guessed and guessed in _ATTACK_MAP:
                key = guessed
        if key:
            tool, reason = _ATTACK_MAP[key]
            out.append({"port": p["port"], "service": p.get("service") or key, "tool": tool, "reason": reason})
    return out
