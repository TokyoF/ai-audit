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
            "poc": f"{service} {host} → login '{login}' password '{password}'"[:400].strip(),
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
            "poc": None,
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

    param_m = re.search(r"Parameter:\s*(\S+)", excerpt, re.IGNORECASE)
    poc = excerpt[:400].strip()
    if param_m:
        poc = f"Parameter: {param_m.group(1)} — {poc}"[:400].strip()

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
        "poc": poc,
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
            "poc": version,
        })

    if "apache httpd 2.2" in v_lower:
        findings.append({
            "title": "Apache 2.2.x vulnerable a DoS por rango (CVE-2011-3192)",
            "severity": "high",
            "cvss": 7.8,
            "description": (
                f"Se detectó Apache httpd 2.2.x ({version}), vulnerable a "
                "denegación de servicio mediante manipulación del encabezado "
                "'Range' (byte-range DoS)."
            ),
            "remediation": "Actualizar Apache httpd a una versión soportada (≥2.4.x).",
            "cve_id": "CVE-2011-3192",
            "poc": version,
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
            "poc": version,
        })
    elif re.search(r"vsftpd 2\.[01]\b", v_lower):
        findings.append({
            "title": f"vsftpd obsoleto ({version})",
            "severity": "medium",
            "cvss": 5.0,
            "description": f"Se detectó una versión obsoleta de vsftpd: {version}.",
            "remediation": "Actualizar vsftpd a una versión soportada.",
            "cve_id": None,
            "poc": version,
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
                    "poc": version,
                })
            if ver_num < 7.7:
                findings.append({
                    "title": "OpenSSH vulnerable a enumeración de usuarios (CVE-2018-15473)",
                    "severity": "medium",
                    "cvss": 5.3,
                    "description": (
                        f"Se detectó OpenSSH {version} (<7.7), vulnerable a "
                        "enumeración de nombres de usuario válidos mediante "
                        "diferencias de tiempo/respuesta en la autenticación."
                    ),
                    "remediation": "Actualizar OpenSSH a ≥7.7.",
                    "cve_id": "CVE-2018-15473",
                    "poc": version,
                })
        except ValueError:
            pass

    if re.search(r"\bopenssh[_\s]+(8\.[5-9]|9\.[0-7])(?!\d)", v_lower):
        findings.append({
            "title": "OpenSSH vulnerable a regreSSHion (CVE-2024-6387)",
            "severity": "high",
            "cvss": 8.1,
            "description": (
                f"Se detectó OpenSSH {version} (8.5p1-9.7p1), vulnerable a una "
                "condición de carrera en el manejador de señales (signal handler "
                "race) que puede permitir ejecución remota de código sin "
                "autenticación (regreSSHion)."
            ),
            "remediation": "Actualizar OpenSSH a ≥9.8p1.",
            "cve_id": "CVE-2024-6387",
            "poc": version,
        })

    samba_m = re.search(r"samba[_\s]+(\d+\.\d+(?:\.\d+)?)", v_lower)
    if samba_m:
        try:
            parts = [int(p) for p in samba_m.group(1).split(".")]
            major_minor = (parts[0], parts[1])
            in_range = (3, 5) <= major_minor <= (4, 6)
            if in_range:
                findings.append({
                    "title": "Samba vulnerable a ejecución remota (CVE-2017-7494 SambaCry)",
                    "severity": "critical",
                    "cvss": 9.8,
                    "description": (
                        f"Se detectó Samba {version} (3.5.0-4.6.x), vulnerable a "
                        "ejecución remota de código mediante carga de una "
                        "biblioteca compartida maliciosa (SambaCry)."
                    ),
                    "remediation": "Actualizar Samba a ≥4.6.4.",
                    "cve_id": "CVE-2017-7494",
                    "poc": version,
                })
        except (ValueError, IndexError):
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
            "poc": m.group(0).strip()[:400],
        })

        findings.extend(_nmap_version_findings(version))

    anon_m = re.search(r"^.*Anonymous FTP login allowed.*$", output, re.IGNORECASE | re.MULTILINE)
    if anon_m:
        findings.append({
            "title": "FTP anónimo habilitado",
            "severity": "medium",
            "cvss": 5.5,
            "description": "El servicio FTP permite inicio de sesión anónimo (sin credenciales), exponiendo potencialmente archivos del servidor.",
            "remediation": "Deshabilitar el acceso anónimo en la configuración del servidor FTP (p. ej. anonymous_enable=NO en vsftpd).",
            "cve_id": None,
            "poc": anon_m.group(0).strip()[:400],
        })

    return findings


def _extract_ftp_anon(output: str) -> list[dict]:
    low = output.lower()
    # curl -v prints "230" on successful anonymous login; "530" means denied.
    success = ("230" in output) or ("login successful" in low) or ("drwx" in low) or ("<dir>" in low)
    denied = "530" in output or "login incorrect" in low or "access denied" in low
    if success and not denied:
        evidence_m = re.search(
            r"^.*(230|login successful|drwx|<dir>).*$",
            output,
            re.IGNORECASE | re.MULTILINE,
        )
        poc = evidence_m.group(0).strip()[:400] if evidence_m else output.strip()[:400]
        return [{
            "title": "FTP anónimo habilitado",
            "severity": "medium",
            "cvss": 5.5,
            "description": "Se confirmó inicio de sesión FTP anónimo (usuario 'anonymous' sin contraseña); el servidor permite listar/descargar archivos sin autenticación.",
            "remediation": "Deshabilitar el acceso anónimo en la configuración del servidor FTP (p. ej. anonymous_enable=NO en vsftpd).",
            "cve_id": None,
            "poc": poc,
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
            "poc": f"{template_id} @ {url}"[:400].strip(),
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
            "poc": stripped[:400],
        })

    return findings


def _extract_whatweb(output: str) -> list:
    findings = []
    try:
        token_pattern = re.compile(r"([A-Za-z0-9\-_]+)\[([^\]]*)\]")

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            tokens = token_pattern.findall(stripped)
            if not tokens:
                continue

            server = None
            techs = []
            php_version = None
            php_token = None

            for name_tok, value_tok in tokens:
                techs.append(f"{name_tok}[{value_tok}]")
                low_name = name_tok.lower()
                if low_name in ("httpserver", "apache", "nginx") and value_tok:
                    if server is None:
                        server = value_tok
                if low_name in ("php",) and value_tok:
                    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", value_tok)
                    if m:
                        php_version = m.group(1)
                        php_token = f"{name_tok}[{value_tok}]"
                if low_name == "x-powered-by" and "php" in value_tok.lower():
                    m = re.search(r"php[/\s]?(\d+\.\d+(?:\.\d+)?)", value_tok, re.IGNORECASE)
                    if m and php_version is None:
                        php_version = m.group(1)
                        php_token = f"{name_tok}[{value_tok}]"

            if server:
                findings.append({
                    "title": f"Tecnología web detectada: {server}",
                    "severity": "info",
                    "cvss": 0.0,
                    "description": (
                        "whatweb detectó las siguientes tecnologías: "
                        + ", ".join(techs)
                    ),
                    "remediation": (
                        "Ocultar banners de versión (ServerTokens Prod / expose_php Off)."
                    ),
                    "cve_id": None,
                    "poc": stripped[:400],
                })

            if php_version and php_version.startswith("5."):
                findings.append({
                    "title": f"PHP obsoleto ({php_version})",
                    "severity": "low",
                    "cvss": 3.0,
                    "description": f"Se detectó una versión obsoleta de PHP: {php_version}.",
                    "remediation": "Actualizar PHP a una versión soportada.",
                    "cve_id": None,
                    "poc": (php_token or php_version)[:400],
                })

            if findings:
                break

        return findings
    except Exception:
        return []


_SENSITIVE_PATH_KEYWORDS = (
    "admin", "backup", "config", ".git", ".env", "db", "sql", "phpmyadmin", "login",
)


def _extract_gobuster(output: str) -> list:
    findings = []
    seen_paths = set()
    try:
        pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)
        for m in pattern.finditer(output):
            if len(findings) >= 15:
                break
            path, code = m.groups()
            path = path.strip()
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)

            low_path = path.lower()
            sensitive = any(k in low_path for k in _SENSITIVE_PATH_KEYWORDS)
            severity = "low" if sensitive else "info"
            cvss = 3.0 if sensitive else 0.0

            line_m = re.search(re.escape(path) + r".*", output)
            raw_line = line_m.group(0).strip() if line_m else f"{path} (Status: {code})"

            findings.append({
                "title": f"Ruta web expuesta: {path}",
                "severity": severity,
                "cvss": cvss,
                "description": f"gobuster descubrió la ruta {path} (HTTP {code}).",
                "remediation": (
                    "Revisar si la ruta debe ser pública; restringir acceso o eliminarla."
                ),
                "cve_id": None,
                "poc": raw_line[:400],
            })

        return findings
    except Exception:
        return []


def _extract_enum4linux(output: str) -> list:
    findings = []
    try:
        low = output.lower()

        shares_m = re.search(
            r"(mapping:\s*ok|sharename|disk\||//[^\s]+/[^\s]+)",
            output,
            re.IGNORECASE,
        )
        if shares_m or "mapping: ok" in low:
            start = max(0, shares_m.start() - 50) if shares_m else 0
            excerpt = output[start:start + 300].strip() if shares_m else output.strip()[:300]
            findings.append({
                "title": "Recursos SMB/Samba enumerables",
                "severity": "medium",
                "cvss": 5.0,
                "description": (
                    "Se enumeraron recursos compartidos o información del dominio "
                    "vía SMB sin autenticación fuerte."
                ),
                "remediation": (
                    "Restringir el acceso anónimo/null-session a SMB; aplicar "
                    "principio de mínimo privilegio."
                ),
                "cve_id": None,
                "poc": excerpt[:400],
            })

        user_lines = re.findall(r"^.*user:\[[^\]]+\].*$", output, re.IGNORECASE | re.MULTILINE)
        if user_lines:
            excerpt = "\n".join(user_lines[:10])[:400]
            findings.append({
                "title": "Usuarios del sistema enumerables vía SMB",
                "severity": "low",
                "cvss": 3.0,
                "description": (
                    "Se enumeraron nombres de usuario del sistema vía SMB sin "
                    "autenticación."
                ),
                "remediation": "Deshabilitar enumeración anónima (RestrictAnonymous).",
                "cve_id": None,
                "poc": excerpt,
            })

        return findings
    except Exception:
        return []


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
        elif name == "whatweb":
            findings = _extract_whatweb(output)
        elif name == "gobuster":
            findings = _extract_gobuster(output)
        elif name == "enum4linux":
            findings = _extract_enum4linux(output)
        else:
            return []

        return _dedupe_by_title(findings)
    except Exception:
        return []
