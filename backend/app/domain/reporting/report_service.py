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

_SEVERITY_LABEL = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}

_METHODOLOGY_PHASES = [
    "Reconocimiento y escaneo de puertos (nmap)",
    "Identificación de servicios y versiones",
    "Enumeración web (whatweb, gobuster, nikto, nuclei)",
    "Pruebas de autenticación (hydra, acceso anónimo FTP)",
    "Pruebas de inyección (sqlmap)",
    "Análisis y reporte de hallazgos",
]

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
    h3 {
        color: #111827;
        font-size: 11pt;
        margin-top: 4px;
        margin-bottom: 4px;
    }
    .subtitle {
        color: #6b7280;
        font-size: 9pt;
        margin-bottom: 14px;
    }
    .cover-wrapper {
        page-break-after: always;
        padding-top: 120pt;
        text-align: center;
    }
    .cover-title {
        font-size: 28pt;
        font-weight: bold;
        color: #111827;
        margin-bottom: 10pt;
    }
    .cover-subtitle {
        font-size: 15pt;
        color: #2563eb;
        margin-bottom: 60pt;
    }
    .cover-target {
        font-size: 20pt;
        font-weight: bold;
        color: #111827;
        border-top: 2px solid #111827;
        border-bottom: 2px solid #111827;
        padding: 14pt 0;
        margin: 0 60pt 40pt 60pt;
    }
    table.cover-meta {
        width: 60%;
        margin: 0 auto;
        border-collapse: collapse;
    }
    table.cover-meta td {
        padding: 6px 10px;
        border: 1px solid #e5e7eb;
        font-size: 9pt;
    }
    table.cover-meta td.label {
        font-weight: bold;
        background-color: #f9fafb;
        width: 40%;
        text-align: left;
    }
    .section-page {
        page-break-before: always;
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
    table.risk-matrix {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 16px;
    }
    table.risk-matrix th {
        background-color: #1f2937;
        color: #ffffff;
        text-align: left;
        padding: 6px;
        font-size: 9pt;
    }
    table.risk-matrix td {
        padding: 6px;
        border: 1px solid #e5e7eb;
        font-size: 9pt;
    }
    ol.methodology li {
        margin-bottom: 6px;
        font-size: 10pt;
    }
    .exec-summary {
        font-size: 10pt;
        margin-bottom: 10px;
        text-align: justify;
    }
    .risk-verdict {
        font-weight: bold;
        padding: 6px 10px;
        color: #ffffff;
        background-color: #dc2626;
        display: inline;
    }
    table.finding-block {
        width: 100%;
        border-collapse: collapse;
        border: 1px solid #d1d5db;
        margin-bottom: 14px;
        page-break-inside: avoid;
    }
    table.finding-block td {
        padding: 6px 8px;
        border: 1px solid #e5e7eb;
        font-size: 9pt;
        vertical-align: top;
    }
    .finding-header-cell {
        background-color: #f3f4f6;
        padding: 0;
    }
    .finding-severity-badge {
        color: #ffffff;
        font-weight: bold;
        padding: 4px 10px;
        font-size: 9pt;
    }
    .finding-title {
        font-weight: bold;
        font-size: 11pt;
        color: #111827;
        padding: 6px 8px;
    }
    .finding-label {
        font-weight: bold;
        color: #374151;
        width: 18%;
        background-color: #f9fafb;
    }
    .poc-box {
        font-family: Courier, monospace;
        font-size: 8pt;
        background-color: #111827;
        color: #d1fae5;
        padding: 8px;
        white-space: pre-wrap;
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

    <div class="cover-wrapper">
        <div class="cover-title">AI-AUDIT</div>
        <div class="cover-subtitle">Informe de Auditoría de Seguridad</div>
        <div class="cover-target">Objetivo: {{ target_host }}</div>
        <table class="cover-meta" cellspacing="0" cellpadding="0">
            <tr><td class="label">ID de auditoría</td><td>{{ audit_id }}</td></tr>
            <tr><td class="label">Estado</td><td>{{ audit_status }}</td></tr>
            <tr><td class="label">Generado el</td><td>{{ generated_at }}</td></tr>
            <tr><td class="label">Inicio</td><td>{{ started_at }}</td></tr>
            <tr><td class="label">Fin</td><td>{{ finished_at }}</td></tr>
        </table>
    </div>

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

    <h2>Resumen ejecutivo</h2>
    <div class="exec-summary">
        Se ha llevado a cabo una auditoría de seguridad sobre el objetivo <strong>{{ target_host }}</strong>,
        identificando un total de <strong>{{ total_vulns }}</strong> hallazgo(s). De estos,
        <strong>{{ severity_counts.get('critical', 0) }}</strong> son de severidad crítica y
        <strong>{{ severity_counts.get('high', 0) }}</strong> de severidad alta.
        Se recomienda priorizar la remediación de los hallazgos críticos y altos descritos en este informe.
    </div>
    <div><span class="risk-verdict">{{ risk_verdict }}</span></div>

    <h2>Resumen de hallazgos</h2>
    <table class="badges-table" cellspacing="0" cellpadding="0">
        <tr>
        {% for sev, count in severity_counts.items() %}
            <td style="background-color:{{ severity_colors.get(sev, '#6b7280') }}; color:#ffffff; font-weight:bold; padding:4px 10px; font-size:9pt;">{{ sev|upper }}: {{ count }}</td>
            <td style="width:6px;"></td>
        {% endfor %}
        </tr>
    </table>

    <h2>Matriz de riesgo</h2>
    <table class="risk-matrix" cellspacing="0" cellpadding="0">
        <thead>
        <tr>
            <th>Severidad</th>
            <th>Cantidad de hallazgos</th>
        </tr>
        </thead>
        <tbody>
        {% for sev in ['critical', 'high', 'medium', 'low', 'info'] %}
        <tr>
            <td style="background-color:{{ severity_colors.get(sev, '#6b7280') }}; color:#ffffff; font-weight:bold;">{{ severity_labels.get(sev, sev|upper) }}</td>
            <td>{{ risk_matrix.get(sev, 0) }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

    <h2>Metodología</h2>
    <ol class="methodology">
        {% for phase in methodology %}
        <li>{{ phase }}</li>
        {% endfor %}
    </ol>

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

    <div class="section-page">
    <h2>Vulnerabilidades detectadas</h2>
    {% for v in vulnerabilities %}
    <table class="finding-block" cellspacing="0" cellpadding="0">
        <tr>
            <td class="finding-header-cell" colspan="2">
                <table cellspacing="0" cellpadding="0" style="width:100%;">
                    <tr>
                        <td style="width:14%; padding:0;">
                            <div class="finding-severity-badge" style="background-color:{{ severity_colors.get(v.severity, '#6b7280') }};">{{ v.severity|upper }}</div>
                        </td>
                        <td class="finding-title">
                            {{ v.title }}
                            {% if v.cvss_score is not none %} (CVSS {{ v.cvss_score }}){% endif %}
                            {% if v.cve_id %} — {{ v.cve_id }}{% endif %}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td class="finding-label">Descripción / Impacto</td>
            <td>{{ v.description }}</td>
        </tr>
        {% if v.poc %}
        <tr>
            <td class="finding-label">Evidencia</td>
            <td><div class="poc-box">{{ v.poc }}</div></td>
        </tr>
        {% endif %}
        <tr>
            <td class="finding-label">Remediación</td>
            <td>{{ v.remediation if v.remediation else "—" }}</td>
        </tr>
    </table>
    {% endfor %}
    </div>

    {% if logs %}
    <div class="section-page">
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
    </div>
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


def _risk_verdict(severity_counts: dict[str, int]) -> str:
    if severity_counts.get("critical", 0) > 0:
        return "Riesgo ALTO"
    if severity_counts.get("high", 0) > 0:
        return "Riesgo MEDIO-ALTO"
    return "Riesgo MODERADO/BAJO"


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
            "poc": getattr(v, "poc", None),
        }
        for v in sorted_vulns
    ]

    log_rows = []
    for log in list(logs)[-100:]:
        content = log.content or ""
        if len(content) > 600:
            content = content[:600] + "…"
        log_rows.append(
            {
                "step_type": log.step_type.value if hasattr(log.step_type, "value") else str(log.step_type),
                "tool_used": log.tool_used,
                "content": content,
            }
        )

    total_vulns = len(vulnerabilities)
    risk_matrix = severity_counts
    risk_verdict = _risk_verdict(severity_counts)

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
        severity_labels=_SEVERITY_LABEL,
        credentials=credentials,
        vulnerabilities=vuln_rows,
        logs=log_rows,
        total_vulns=total_vulns,
        risk_matrix=risk_matrix,
        methodology=_METHODOLOGY_PHASES,
        risk_verdict=risk_verdict,
    )

    import io
    from xhtml2pdf import pisa

    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(src=rendered_html, dest=buffer, encoding="utf-8")
    if pisa_status.err:
        raise RuntimeError("Error al generar el PDF del informe")
    return buffer.getvalue()
