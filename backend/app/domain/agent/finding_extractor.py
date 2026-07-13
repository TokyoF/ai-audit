"""Deterministic extraction of pentest findings from raw tool output.

This module is intentionally dependency-free (only ``re`` from the standard
library) so it can be used by the agent to auto-report discoveries without
relying on the LLM emitting a ``FINDING`` block.

Public API:
    extract_findings(tool_name, command, output) -> list[dict]
"""

import re

__all__ = ["extract_findings", "normalize_finding_title"]

_KNOWN_SERVICES = [
    "ssh", "ftp", "ftps", "http-get", "http-post-form", "https",
    "mysql", "mssql", "postgres", "rdp", "smb", "smtp", "telnet",
    "pop3", "imap", "vnc",
]

_SEVERITY_CVSS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
    "unknown": 0.0,
}


def normalize_finding_title(title: str) -> str:
    """Normalize a finding title for cross-scan deduplication.
    Strips parenthetical version banners (including nested ones like
    '((Ubuntu))') so slightly different version strings for the same issue
    collapse to one dedup key.
    """
    if not title:
        return ""
    stripped = title
    prev = None
    while prev != stripped:
        prev = stripped
        stripped = re.sub(r"\([^()]*\)", " ", stripped)
    return re.sub(r"\s+", " ", stripped).strip().lower()


def _dedupe_by_title(findings: list) -> list:
    seen = set()
    result = []
    for f in findings:
        title = f.get("title")
        if title in seen:
            continue
        seen.add(title)
        result.append(f)
    return result


def _guess_service_from_command(command: str) -> str:
    if not command:
        return "servicio"
    low = command.lower()
    tokens = re.split(r"\s+", command.strip())
    if tokens:
        last = re.sub(r"^\w+://", "", tokens[-1].lower())
        for svc in _KNOWN_SERVICES:
            if last == svc:
                return svc
    for svc in _KNOWN_SERVICES:
        if re.search(rf"\b{re.escape(svc)}\b", low):
            return svc
    return "servicio"


def _extract_hydra(command: str, output: str) -> list:
    findings = []
    pattern = re.compile(
        r"\[\d+\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)",
        re.IGNORECASE,
    )
    matches = list(pattern.finditer(output))

    for m in matches:
        service, host, login, password = m.groups()
        service = service.strip()
        findings.append({
            "title": f"Credenciales débiles en {service.upper()} ({login})",
            "severity": "critical",
            "cvss": 9.8,
            "description": (
                f"Se descubrieron credenciales válidas en el servicio {service} "
                f"del host {host}: usuario '{login}', contraseña '{password}'."
            ),
            "remediation": (
                "Usar contraseñas robustas y únicas, deshabilitar autenticación "
                "por contraseña donde sea posible (usar llaves), aplicar "
                "rate-limiting y bloqueo por intentos fallidos."
            ),
            "cve_id": None,
        })

    low = output.lower()
    if not matches and (
        "valid pair found" in low
        or "successfully completed, 1 valid password" in low
    ):
        service = _guess_service_from_command(command)
        findings.append({
            "title": f"Credenciales débiles en {service.upper()} (desconocido)",
            "severity": "critical",
            "cvss": 9.8,
            "description": (
                f"Hydra reportó un par de credenciales válido para el servicio "
                f"{service}, pero no se pudo parsear la línea exacta."
            ),
            "remediation": (
                "Usar contraseñas robustas y únicas, deshabilitar autenticación "
                "por contraseña donde sea posible (usar llaves), aplicar "
                "rate-limiting y bloqueo por intentos fallidos."
            ),
            "cve_id": None,
        })

    return findings


def _extract_sqlmap(output: str) -> list:
    m = re.search(
        r"is vulnerable|sqlmap identified the following injection|parameter:.*?type:",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return []

    start = max(0, m.start() - 100)
    end = min(len(output), m.end() + 300)
    excerpt = output[start:end].strip()

    return [{
        "title": "Inyección SQL detectada",
        "severity": "critical",
        "cvss": 9.8,
        "description": f"sqlmap detectó una vulnerabilidad de inyección SQL:\n{excerpt}",
        "remediation": (
            "Usar consultas parametrizadas / prepared statements, validar y "
            "sanear entradas, aplicar menor privilegio en la BD."
        ),
        "cve_id": None,
    }]


def _nmap_version_findings(version: str) -> list:
    findings = []
    if not version:
        return findings
    v_lower = version.lower()

    if "apache httpd 2.2" in v_lower or "apache httpd 2.0" in v_lower:
        findings.append({
            "title": f"Servidor web Apache obsoleto ({version})",
            "severity": "medium",
            "cvss": 5.3,
            "description": f"Se detectó una versión obsoleta de Apache httpd: {version}.",
            "remediation": "Actualizar Apache a una versión soportada.",
            "cve_id": None,
        })

    if "vsftpd 2.3.4" in v_lower:
        findings.append({
            "title": "vsftpd 2.3.4 (backdoor conocido)",
            "severity": "high",
            "cvss": 8.8,
            "description": (
                f"Se detectó vsftpd 2.3.4 ({version}), versión con un backdoor conocido."
            ),
            "remediation": (
                "Actualizar vsftpd inmediatamente; la 2.3.4 contiene un backdoor."
            ),
            "cve_id": "CVE-2011-2523",
        })
    elif re.search(r"vsftpd 2\.[01]\b", v_lower):
        findings.append({
            "title": f"vsftpd obsoleto ({version})",
            "severity": "medium",
            "cvss": 5.0,
            "description": f"Se detectó una versión obsoleta de vsftpd: {version}.",
            "remediation": "Actualizar vsftpd a una versión soportada.",
            "cve_id": None,
        })

    m = re.search(r"openssh[_\s]+(\d+\.\d+)", version, re.IGNORECASE)
    if m:
        try:
            ver_num = float(m.group(1))
            if ver_num < 7.0:
                findings.append({
                    "title": f"OpenSSH obsoleto ({version})",
                    "severity": "medium",
                    "cvss": 5.0,
                    "description": f"Se detectó una versión obsoleta de OpenSSH: {version}.",
                    "remediation": "Actualizar OpenSSH.",
                    "cve_id": None,
                })
        except ValueError:
            pass

    return findings


def _extract_nmap(output: str) -> list:
    findings = []
    pattern = re.compile(
        r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+([\w\-/?]+)?\s*(.*)$",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in pattern.finditer(output):
        port, proto, service, version = m.groups()
        service = (service or "").strip() or "desconocido"
        version = (version or "").strip()

        findings.append({
            "title": f"Puerto abierto {port}/{proto} ({service})",
            "severity": "info",
            "cvss": 0.0,
            "description": (
                f"Servicio {service} detectado en {port}/{proto}. "
                f"Versión: {version or 'desconocida'}."
            ),
            "remediation": (
                "Cerrar o filtrar el puerto si el servicio no es necesario; "
                "restringir acceso por firewall."
            ),
            "cve_id": None,
        })

        findings.extend(_nmap_version_findings(version))

    if re.search(r"Anonymous FTP login allowed", output, re.IGNORECASE):
        findings.append({
            "title": "FTP anónimo habilitado",
            "severity": "medium",
            "cvss": 5.5,
            "description": "El servicio FTP permite inicio de sesión anónimo (sin credenciales), exponiendo potencialmente archivos del servidor.",
            "remediation": "Deshabilitar el acceso anónimo en la configuración del servidor FTP (p. ej. anonymous_enable=NO en vsftpd).",
            "cve_id": None,
        })

    return findings


def _extract_ftp_anon(output: str) -> list[dict]:
    low = output.lower()
    # curl -v prints "230" on successful anonymous login; "530" means denied.
    success = ("230" in output) or ("login successful" in low) or ("drwx" in low) or ("<dir>" in low)
    denied = "530" in output or "login incorrect" in low or "access denied" in low
    if success and not denied:
        return [{
            "title": "FTP anónimo habilitado",
            "severity": "medium",
            "cvss": 5.5,
            "description": "Se confirmó inicio de sesión FTP anónimo (usuario 'anonymous' sin contraseña); el servidor permite listar/descargar archivos sin autenticación.",
            "remediation": "Deshabilitar el acceso anónimo en la configuración del servidor FTP (p. ej. anonymous_enable=NO en vsftpd).",
            "cve_id": None,
        }]
    return []


def _extract_nuclei(output: str) -> list:
    findings = []
    pattern = re.compile(
        r"\[([^\]]+)\]\s*\[[^\]]+\]\s*\[(critical|high|medium|low|info|unknown)\]\s*(\S+)?",
        re.IGNORECASE,
    )
    for m in pattern.finditer(output):
        template_id, severity, url = m.groups()
        severity = severity.lower()
        if severity == "unknown":
            severity = "info"
        cvss = _SEVERITY_CVSS.get(severity, 0.0)
        url = url or "URL desconocida"

        cve_id = None
        if re.match(r"^CVE-\d{4}-\d+", template_id):
            cve_id = template_id

        findings.append({
            "title": f"Nuclei: {template_id}",
            "severity": severity,
            "cvss": cvss,
            "description": f"Nuclei detectó el hallazgo '{template_id}' en {url}.",
            "remediation": "Revisar y remediar según la plantilla de nuclei indicada.",
            "cve_id": cve_id,
        })

    return findings


def _extract_nikto(output: str) -> list:
    findings = []
    keywords = ("osvdb", "vulnerab", "outdated", "xss", "sql")

    for line in output.splitlines():
        if len(findings) >= 10:
            break
        stripped = line.strip()
        if not stripped.startswith("+ "):
            continue
        low = stripped.lower()
        if not any(k in low for k in keywords):
            continue

        findings.append({
            "title": f"Nikto: {stripped[:80]}",
            "severity": "medium",
            "cvss": 5.0,
            "description": stripped,
            "remediation": (
                "Revisar el hallazgo reportado por nikto y aplicar la "
                "corrección correspondiente."
            ),
            "cve_id": None,
        })

    return findings


def extract_findings(tool_name: str, command: str, output: str) -> list:
    """Return a list of structured findings extracted from raw tool output.

    Never raises; returns [] on no matches, empty output, or unknown tool.
    """
    try:
        if not output or not tool_name:
            return []

        name = tool_name.strip().lower()
        command = command or ""

        if name == "hydra":
            findings = _extract_hydra(command, output)
        elif name == "sqlmap":
            findings = _extract_sqlmap(output)
        elif name == "nmap":
            findings = _extract_nmap(output)
        elif name == "nuclei":
            findings = _extract_nuclei(output)
        elif name == "nikto":
            findings = _extract_nikto(output)
        elif name == "ftp_anon":
            findings = _extract_ftp_anon(output)
        else:
            return []

        return _dedupe_by_title(findings)
    except Exception:
        return []
