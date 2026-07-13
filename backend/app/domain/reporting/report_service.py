"""Pure PDF report generation for audits."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from jinja2 import Environment

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0891b2",
}

_CREDENTIALS_RE = re.compile(r"usuario '([^']+)', contrase[ñn]a '([^']+)'")

_TEMPLATE_SOURCE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{{ report_title }}</title>
<style>
    @page {
        size: a4 portrait;
        margin: 2cm;
    }
    body {
        font-family: Helvetica, Arial, sans-serif;
        color: #1f2937;
        font-size: 10pt;
        line-height: 1.5;
    }
    h1 {
        color: #111827;
        font-size: 18pt;
        border-bottom: 3px solid #111827;
        padding-bottom: 8px;
        margin-bottom: 4px;
    }
    h2 {
        color: #111827;
        font-size: 13pt;
        margin-top: 20px;
        margin-bottom: 8px;
        border-left: 4px solid #2563eb;
        padding-left: 8px;
    }
    .subtitle {
        color: #6b7280;
        font-size: 9pt;
        margin-bottom: 14px;
    }
    table.meta-table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 12px;
    }
    .meta-table td {
        padding: 4px 8px;
        border: 1px solid #e5e7eb;
    }
    .meta-table td.label {
        font-weight: bold;
        background-color: #f9fafb;
        width: 30%;
    }
    table.badges-table {
        margin: 10px 0;
    }
    table.credentials-table {
        width: 100%;
        margin-bottom: 14px;
    }
    table.vulns {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 16px;
    }
    table.vulns th {
        background-color: #1f2937;
        color: #ffffff;
        text-align: left;
        padding: 6px;
        font-size: 9pt;
    }
    table.vulns td {
        padding: 6px;
        border: 1px solid #e5e7eb;
        vertical-align: top;
        font-size: 9pt;
    }
    table.logs-table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 10px;
    }
    table.logs-table th {
        background-color: #1f2937;
        color: #ffffff;
        text-align: left;
        padding: 4px;
        font-size: 8pt;
    }
    table.logs-table td {
        padding: 4px;
        border: 1px solid #f3f4f6;
        vertical-align: top;
        font-size: 8pt;
    }
    .footer-note {
        margin-top: 20px;
        font-size: 8pt;
        color: #9ca3af;
        border-top: 1px solid #e5e7eb;
        padding-top: 8px;
    }
</style>
</head>
<body>
    <h1>{{ report_title }}</h1>
    <div class="subtitle">Generado el {{ generated_at }}</div>

    <table class="meta-table" cellspacing="0" cellpadding="0">
        <tr><td class="label">Objetivo (host)</td><td>{{ target_host }}</td></tr>
        <tr><td class="label">ID de auditoría</td><td>{{ audit_id }}</td></tr>
        <tr><td class="label">Estado</td><td>{{ audit_status }}</td></tr>
        <tr><td class="label">Inicio</td><td>{{ started_at }}</td></tr>
        <tr><td class="label">Fin</td><td>{{ finished_at }}</td></tr>
        {% if audit_summary %}
        <tr><td class="label">Resumen</td><td>{{ audit_summary }}</td></tr>
        {% endif %}
    </table>

    <h2>Resumen de hallazgos</h2>
    <table class="badges-table" cellspacing="0" cellpadding="0">
        <tr>
        {% for sev, count in severity_counts.items() %}
            <td style="background-color:{{ severity_colors.get(sev, '#6b7280') }}; color:#ffffff; font-weight:bold; padding:4px 10px; font-size:9pt;">{{ sev|upper }}: {{ count }}</td>
            <td style="width:6px;"></td>
        {% endfor %}
        </tr>
    </table>

    {% if credentials %}
    <h2>⚠ Credenciales comprometidas</h2>
    <table class="credentials-table" cellspacing="0" cellpadding="0">
        {% for cred in credentials %}
        <tr>
            <td style="background-color:#fef2f2; border:1px solid #dc2626; padding:8px;">
                <div style="font-weight:bold; color:#991b1b; margin-bottom:4px;">{{ cred.title }}</div>
                {% if cred.login and cred.password %}
                <div style="font-family:Courier; color:#111827;">usuario: {{ cred.login }} | contraseña: {{ cred.password }}</div>
                {% else %}
                <div style="font-family:Courier; color:#111827;">{{ cred.description }}</div>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    <h2>Vulnerabilidades detectadas</h2>
    <table class="vulns" cellspacing="0" cellpadding="0">
        <thead>
        <tr>
            <th>Severidad</th>
            <th>Título</th>
            <th>CVSS</th>
            <th>CVE</th>
            <th>Descripción</th>
            <th>Remediación</th>
        </tr>
        </thead>
        <tbody>
        {% for v in vulnerabilities %}
        <tr>
            <td style="background-color:{{ severity_colors.get(v.severity, '#6b7280') }}; color:#ffffff; font-weight:bold; text-align:center; padding:4px 8px;">{{ v.severity|upper }}</td>
            <td>{{ v.title }}</td>
            <td>{{ v.cvss_score if v.cvss_score is not none else "—" }}</td>
            <td>{{ v.cve_id if v.cve_id else "—" }}</td>
            <td>{{ v.description }}</td>
            <td>{{ v.remediation if v.remediation else "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

    {% if logs %}
    <h2>Apéndice: registro de actividad (últimas entradas)</h2>
    <table class="logs-table" cellspacing="0" cellpadding="0">
        <thead>
        <tr>
            <th>Tipo</th>
            <th>Herramienta</th>
            <th>Contenido</th>
        </tr>
        </thead>
        <tbody>
        {% for log in logs %}
        <tr>
            <td style="font-weight:bold; color:#2563eb;">{{ log.step_type|upper }}</td>
            <td>{{ log.tool_used if log.tool_used else "—" }}</td>
            <td>{{ log.content }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <div class="footer-note">
        Este informe fue generado automáticamente por AI-AUDIT. Verifique manualmente los hallazgos críticos antes de tomar acciones correctivas.
    </div>
</body>
</html>
"""


def _severity_value(severity) -> str:
    return severity.value if hasattr(severity, "value") else str(severity)


def _fmt_datetime(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _extract_credentials(vulnerabilities: list) -> list[dict]:
    credentials = []
    for vuln in vulnerabilities:
        title = vuln.title or ""
        if not title.lower().startswith("credenciales"):
            continue
        description = vuln.description or ""
        match = _CREDENTIALS_RE.search(description)
        if match:
            login, password = match.group(1), match.group(2)
        else:
            login, password = None, None
        credentials.append(
            {
                "title": title,
                "login": login,
                "password": password,
                "description": description,
            }
        )
    return credentials


def build_audit_pdf(*, audit, target, vulnerabilities: list, logs: list) -> bytes:
    """Build a PDF report for an audit and return the raw PDF bytes."""
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: _SEVERITY_RANK.get(_severity_value(v.severity), 99),
    )

    severity_counts: dict[str, int] = {}
    for vuln in sorted_vulns:
        sev = _severity_value(vuln.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    credentials = _extract_credentials(sorted_vulns)

    vuln_rows = [
        {
            "severity": _severity_value(v.severity),
            "title": v.title,
            "cvss_score": v.cvss_score,
            "cve_id": v.cve_id,
            "description": v.description,
            "remediation": v.remediation,
        }
        for v in sorted_vulns
    ]

    log_rows = []
    for log in list(logs)[-40:]:
        content = log.content or ""
        if len(content) > 300:
            content = content[:300] + "…"
        log_rows.append(
            {
                "step_type": log.step_type.value if hasattr(log.step_type, "value") else str(log.step_type),
                "tool_used": log.tool_used,
                "content": content,
            }
        )

    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE_SOURCE)
    rendered_html = template.render(
        report_title="Informe de Auditoría de Seguridad — AI-AUDIT",
        generated_at=_fmt_datetime(datetime.now(timezone.utc)),
        target_host=target.host if target else "N/D",
        audit_id=str(audit.id),
        audit_status=_severity_value(audit.status) if hasattr(audit.status, "value") else str(audit.status),
        started_at=_fmt_datetime(getattr(audit, "started_at", None)),
        finished_at=_fmt_datetime(getattr(audit, "finished_at", None)),
        audit_summary=getattr(audit, "summary", None),
        severity_counts=severity_counts,
        severity_colors=_SEVERITY_COLOR,
        credentials=credentials,
        vulnerabilities=vuln_rows,
        logs=log_rows,
    )

    import io
    from xhtml2pdf import pisa

    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(src=rendered_html, dest=buffer, encoding="utf-8")
    if pisa_status.err:
        raise RuntimeError("Error al generar el PDF del informe")
    return buffer.getvalue()
