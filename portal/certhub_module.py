"""Módulo CertHub: assinatura de código e inventário de certificados."""
from datetime import timedelta

from django.utils import timezone

from . import modules
from .modules import Module, NavItem

CERTHUB = Module(
    key="certhub",
    name="CertHub",
    description="Certificados: assinatura de código e inventário de certificados.",
    icon="lock",
    url_prefix="/certhub/",
    home_url_name="portal:certificates",
    access_perm="portal.access_certhub",
    nav=[
        NavItem("Assinar ficheiro", "signing:sign", "pen", "signing.can_sign"),
        NavItem("Certificados de assinatura", "portal:certificates", "lock"),
        NavItem("Inventário", "inventory:list", "archive", "inventory.view_inventorycertificate"),
        NavItem("Histórico", "portal:history", "clock"),
        NavItem("Tokens de API", "portal:tokens", "key", "signing.can_sign"),
        NavItem("Todos os tokens", "portal:tokens_all", "key", "portal.manage_tokens"),
        NavItem("Definições", "portal:settings", "cog", "portal.manage_settings"),
    ],
    permission_groups=[
        ("Assinatura de código", [
            ("signing.can_sign", "Assinar ficheiros", "Usar a página de assinatura e a API, e gerir os seus próprios tokens."),
            ("portal.view_all_history", "Ver o histórico de todos", "Sem isto só vê as suas próprias assinaturas."),
        ]),
        ("Inventário de certificados", [
            ("inventory.view_inventorycertificate", "Ver o inventário", "Lista e detalhe dos certificados carregados no inventário."),
            ("inventory.manage_inventory", "Gerir o inventário", "Carregar, editar e apagar certificados do inventário."),
        ]),
        ("Administração do CertHub", [
            ("portal.manage_certificates", "Gerir certificados de assinatura", "Registar, editar, testar e desativar certificados."),
            ("portal.manage_tokens", "Gerir tokens de todos", "Ver e revogar tokens de qualquer utilizador."),
            ("portal.manage_settings", "Gerir definições do CertHub", "SignTool, timestamp, limites, extensões e validade dos tokens."),
        ]),
    ],
    dashboard_template="portal/widgets/certhub.html",
)


def certhub_dashboard(request):
    from signing.models import SigningCertificate, SigningRequest

    user = request.user
    now = timezone.now()
    certs = list(SigningCertificate.objects.all())
    reqs = SigningRequest.objects.select_related("user", "certificate")
    if not user.has_perm("portal.view_all_history"):
        reqs = reqs.filter(user=user)
    month = reqs.filter(created_at__gte=now - timedelta(days=30))
    stats = {
        "active": sum(c.status == "ok" for c in certs),
        "expiring": sum(c.status == "expiring" for c in certs),
        "expired": sum(c.status == "expired" for c in certs),
        "signed_30d": month.filter(status=SigningRequest.Status.OK).count(),
        "failed_30d": month.filter(status=SigningRequest.Status.FAILED).count(),
    }
    attention = sorted((c for c in certs if c.is_active and c.attention or c.status == "expired"),
                       key=lambda c: c.not_after)
    inv = None
    if user.has_perm("inventory.view_inventorycertificate"):
        from inventory.models import ALERT_DAYS, InventoryCertificate

        allc = InventoryCertificate.objects.all()
        inv = {
            "total": allc.count(),
            "expiring": allc.filter(not_after__gt=now, not_after__lte=now + timedelta(days=ALERT_DAYS)).count(),
            "expired": allc.filter(not_after__lte=now).count(),
            "next": allc.filter(not_after__gt=now).order_by("not_after")[:5],
        }
    return {"stats": stats, "attention": attention, "recent": reqs[:8], "total_certs": len(certs), "inv": inv,
            "can_sign": user.has_perm("signing.can_sign")}


CERTHUB.dashboard = certhub_dashboard


def register_all():
    modules.register(CERTHUB)
