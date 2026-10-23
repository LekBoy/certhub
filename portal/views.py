from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from signing.models import SigningCertificate, SigningRequest, SigningToken, SiteSettings

from . import modules
from .audit import audit


def _visible_requests(user):
    """Quem tem «ver o histórico de todos» vê tudo; os restantes só os seus pedidos."""
    qs = SigningRequest.objects.select_related("user", "certificate")
    return qs if user.has_perm("portal.view_all_history") else qs.filter(user=user)


@login_required
def dashboard(request):
    """Painel da plataforma: um bloco por módulo a que o utilizador tem acesso."""
    widgets = []
    for module in modules.accessible_modules(request.user):
        if module.dashboard and module.dashboard_template:
            widgets.append({"module": module, "template": module.dashboard_template, "d": module.dashboard(request)})
    return render(request, "portal/dashboard.html", {"widgets": widgets})


@login_required
def certificates(request):
    return render(request, "portal/certificates.html", {"certificates": SigningCertificate.objects.order_by("not_after")})


@login_required
def history(request):
    qs = _visible_requests(request.user)
    status = request.GET.get("status", "")
    q = request.GET.get("q", "").strip()
    if status in SigningRequest.Status.values:
        qs = qs.filter(status=status)
    if q:
        qs = qs.filter(Q(filename__icontains=q) | Q(sha256_original__startswith=q.lower())
                       | Q(sha256_signed__startswith=q.lower()) | Q(user__username__icontains=q))
    page = Paginator(qs, 20).get_page(request.GET.get("page"))
    keep = "&".join(f"{k}={v}" for k, v in (("status", status), ("q", q)) if v)
    return render(request, "portal/history.html", {
        "page": page, "status": status, "q": q, "keep": keep,
        "all_users": request.user.has_perm("portal.view_all_history"),
    })


@login_required
@permission_required("signing.can_sign", raise_exception=True)
def tokens(request):
    raw = None
    site = SiteSettings.load()
    if request.method == "POST":
        name = request.POST.get("name", "").strip()[:255]
        if not name:
            messages.error(request, "Indique uma descrição para o token (ex.: pipeline PAD).")
        else:
            token = SigningToken(user=request.user, name=name)
            raw = token.set_new_token(site.token_valid_days)
            token.save()
            audit(request, "token_created", f"{name} ({request.user.username})")
    return render(request, "portal/tokens.html", {
        "tokens": SigningToken.objects.filter(user=request.user).order_by("-created_at"),
        "raw_token": raw, "api_url": request.build_absolute_uri(reverse("api_sign")),
        "valid_days": site.token_valid_days,
        "usable_certs": SigningCertificate.usable_for(request.user),
    })


@login_required
@require_POST
def revoke_token(request, pk):
    token = get_object_or_404(SigningToken, pk=pk, user=request.user)
    token.is_active = False
    token.save(update_fields=["is_active"])
    audit(request, "token_revoked", f"{token.name} ({request.user.username})")
    messages.success(request, f"Token «{token.name}» revogado.")
    return redirect("portal:tokens")
