"""Avisos por e-mail de certificados perto de expirar (Outlook / Exchange / Microsoft 365).

Os módulos declaram o que expira (Module.expiry_items). Aqui decide-se o que avisar, envia-se um só e-mail
resumo e regista-se cada aviso para não repetir. Corre por agendamento: `python manage.py send_expiry_alerts`.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date

from django.core.mail import EmailMultiAlternatives, get_connection
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape

from . import modules
from .models import NotificationLog, NotificationSettings

SMTP_PASSWORD_ENV = "INFRAHUB_SMTP_PASSWORD"
GRAPH_SECRET_ENV = "INFRAHUB_GRAPH_CLIENT_SECRET"
EXPIRED = -1


class SendError(Exception):
    pass


@dataclass
class Alert:
    item: object  # ExpiryItem
    days_left: int
    threshold: int  # EXPIRED (-1) ou o limiar em dias

    @property
    def url(self) -> str:
        return reverse(self.item.url_name, args=self.item.url_args or ())


def _as_date(value) -> date:
    if hasattr(value, "hour"):  # datetime
        if timezone.is_aware(value):
            value = timezone.localtime(value)
        return value.date()
    return value


def threshold_for(days_left: int, thresholds: list[int], notify_expired: bool):
    """Limiar aplicável: o menor limiar >= dias que faltam; -1 se já expirou; None se ainda não é altura."""
    if days_left < 0:
        return EXPIRED if notify_expired else None
    for t in sorted(thresholds):
        if days_left <= t:
            return t
    return None


def pending_alerts(cfg: NotificationSettings, today: date | None = None, force: bool = False) -> list[Alert]:
    today = today or timezone.localdate()
    thresholds = cfg.threshold_list
    out = []
    for module in modules.all_modules():
        if not module.expiry_items or not modules.is_enabled(module):
            continue
        for item in module.expiry_items():
            if not item.expires_at:
                continue
            exp = _as_date(item.expires_at)
            days_left = (exp - today).days
            t = threshold_for(days_left, thresholds, cfg.notify_expired)
            if t is None:
                continue
            if not force and NotificationLog.objects.filter(
                kind=NotificationLog.KIND_EXPIRY, item_key=item.key, threshold=t, expires_on=exp, ok=True
            ).exists():
                continue
            out.append(Alert(item, days_left, t))
    out.sort(key=lambda a: a.days_left)
    return out


def _when(days_left: int) -> str:
    if days_left < 0:
        return f"expirou há {-days_left} dia(s)"
    if days_left == 0:
        return "expira hoje"
    return f"expira em {days_left} dia(s)"


def _link(cfg, alert) -> str:
    base = (cfg.base_url or "").rstrip("/")
    return f"{base}{alert.url}" if base else ""


def build_message(cfg: NotificationSettings, alerts: list[Alert]) -> tuple[str, str, str]:
    expired = sum(1 for a in alerts if a.days_left < 0)
    subject = f"[InfraHub] {len(alerts)} certificado(s) a precisar de atenção"
    if expired:
        subject += f" ({expired} expirado(s))"
    lines, rows = [], []
    for a in alerts:
        exp = a.item.expires_at.strftime("%d/%m/%Y") if a.item.expires_at else "—"
        link = _link(cfg, a)
        lines.append(f"- {a.item.name} ({a.item.area}): {_when(a.days_left)} — {exp}"
                     + (f"\n  {a.item.detail}" if a.item.detail else "") + (f"\n  {link}" if link else ""))
        color = "#b91c1c" if a.days_left < 0 or a.days_left <= 7 else "#b45309"
        name = escape(a.item.name)
        if link:
            name = f'<a href="{escape(link)}" style="color:#0b3d6e;text-decoration:none">{name}</a>'
        rows.append(
            f'<tr><td style="padding:8px 10px;border-bottom:1px solid #e2e8f0">{name}'
            f'<div style="font-size:12px;color:#64748b">{escape(a.item.area)}'
            + (f" · {escape(a.item.detail)}" if a.item.detail else "") + "</div></td>"
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap">{exp}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap;color:{color};font-weight:600">'
            f"{escape(_when(a.days_left))}</td></tr>")
    text = ("Certificados a expirar:\n\n" + "\n".join(lines)
            + "\n\nEste aviso é enviado uma só vez por limiar. — InfraHub")
    html = (
        '<div style="font-family:Segoe UI,Arial,sans-serif;color:#0f172a;font-size:14px">'
        '<h2 style="margin:0 0 12px;color:#0b3d6e">Certificados a precisar de atenção</h2>'
        '<table style="border-collapse:collapse;width:100%;max-width:720px">'
        '<tr style="background:#f1f5f9;text-align:left"><th style="padding:8px 10px">Certificado</th>'
        '<th style="padding:8px 10px">Expira</th><th style="padding:8px 10px">Estado</th></tr>'
        + "".join(rows) + "</table>"
        '<p style="color:#64748b;font-size:12px;margin-top:16px">Este aviso é enviado uma só vez por limiar. — InfraHub</p></div>')
    return subject, text, html


# ------------------------------------------------------------------ transportes
def _from_header(cfg) -> str:
    return f"{cfg.from_name} <{cfg.from_address}>" if cfg.from_name else cfg.from_address


def _send_smtp(cfg, subject, text, html, recipients):
    if not cfg.smtp_host:
        raise SendError("Servidor SMTP não configurado.")
    conn = get_connection(
        host=cfg.smtp_host, port=cfg.smtp_port,
        username=cfg.smtp_username or None, password=os.environ.get(SMTP_PASSWORD_ENV) or None,
        use_tls=cfg.smtp_security == "starttls", use_ssl=cfg.smtp_security == "ssl", timeout=20,
        fail_silently=False)
    msg = EmailMultiAlternatives(subject, text, _from_header(cfg), recipients, connection=conn)
    msg.attach_alternative(html, "text/html")
    try:
        msg.send()
    except Exception as exc:  # smtplib / socket / ssl
        raise SendError(f"SMTP: {exc}") from exc


def _http_json(url, data: bytes, headers: dict):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise SendError(f"Graph HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise SendError(f"Graph: {exc}") from exc


def _send_graph(cfg, subject, text, html, recipients):
    secret = os.environ.get(GRAPH_SECRET_ENV)
    if not (cfg.graph_tenant_id and cfg.graph_client_id and secret):
        raise SendError("Microsoft Graph não configurado (Tenant ID, Client ID e variável do segredo).")
    if not cfg.from_address:
        raise SendError("Indique o e-mail remetente (a caixa de correio de onde sai).")
    token = _http_json(
        f"https://login.microsoftonline.com/{urllib.parse.quote(cfg.graph_tenant_id)}/oauth2/v2.0/token",
        urllib.parse.urlencode({
            "client_id": cfg.graph_client_id, "client_secret": secret, "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default"}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"}).get("access_token")
    if not token:
        raise SendError("Graph: não foi devolvido token de acesso.")
    payload = {"message": {
        "subject": subject, "body": {"contentType": "HTML", "content": html},
        "toRecipients": [{"emailAddress": {"address": r}} for r in recipients]}, "saveToSentItems": False}
    _http_json(f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(cfg.from_address)}/sendMail",
               json.dumps(payload).encode(), {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})


def deliver(cfg, subject, text, html, recipients):
    if not recipients:
        raise SendError("Sem destinatários.")
    if not cfg.from_address:
        raise SendError("Indique o e-mail do remetente.")
    (_send_graph if cfg.transport == "graph" else _send_smtp)(cfg, subject, text, html, recipients)


# ------------------------------------------------------------------ operações
def run_alerts(dry_run: bool = False, force: bool = False, today: date | None = None) -> dict:
    cfg = NotificationSettings.load()
    result = {"alerts": 0, "sent": False, "error": "", "skipped": ""}
    if not cfg.enabled and not force:
        result["skipped"] = "Notificações desativadas."
        return result
    alerts = pending_alerts(cfg, today, force)
    result["alerts"] = len(alerts)
    result["items"] = [(a.item.name, a.days_left) for a in alerts]
    if not alerts or dry_run:
        if not dry_run:
            _remember(cfg, "Nada para avisar." if not alerts else "")
        return result
    subject, text, html = build_message(cfg, alerts)
    recipients = cfg.recipient_list
    try:
        deliver(cfg, subject, text, html, recipients)
        ok, err = True, ""
    except SendError as exc:
        ok, err = False, str(exc)
    for a in alerts:
        NotificationLog.objects.create(
            kind=NotificationLog.KIND_EXPIRY, item_key=a.item.key, item_name=a.item.name[:255],
            threshold=a.threshold,
            expires_on=_as_date(a.item.expires_at),
            subject=subject, recipients=", ".join(recipients), ok=ok, error=err)
    result.update(sent=ok, error=err)
    _remember(cfg, f"{len(alerts)} aviso(s) enviado(s)." if ok else f"Falhou: {err}"[:500])
    return result


def send_test(user_label: str = "") -> tuple[bool, str]:
    cfg = NotificationSettings.load()
    subject = "[InfraHub] E-mail de teste"
    text = "Se recebeu esta mensagem, as notificações por e-mail do InfraHub estão a funcionar."
    html = f"<p style=\"font-family:Segoe UI,Arial,sans-serif\">{escape(text)}</p>"
    recipients = cfg.recipient_list
    try:
        deliver(cfg, subject, text, html, recipients)
        ok, err = True, ""
    except SendError as exc:
        ok, err = False, str(exc)
    NotificationLog.objects.create(kind=NotificationLog.KIND_TEST, subject=subject, recipients=", ".join(recipients),
                                   ok=ok, error=err, item_name=user_label[:255])
    return ok, err


def _remember(cfg, summary):
    cfg.last_run_at = timezone.now()
    cfg.last_run_summary = summary
    cfg.save(update_fields=["last_run_at", "last_run_summary"])
