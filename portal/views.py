from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from signing.models import SigningCertificate, SigningRequest, SigningToken


def _visible_requests(user):
    """Auditores (view_signingrequest) veem tudo; os restantes só os seus pedidos."""
    qs = SigningRequest.objects.select_related("user", "certificate")
    return qs if user.has_perm("signing.view_signingrequest") else qs.filter(user=user)


@login_required
def dashboard(request):
    now = timezone.now()
    certs = list(SigningCertificate.objects.all())
    reqs = _visible_requests(request.user)
    month = reqs.filter(created_at__gte=now - timedelta(days=30))
    stats = {
        "active": sum(c.status == "ok" for c in certs),
        "expiring": sum(c.status == "expiring" for c in certs),
        "expired": sum(c.status == "expired" for c in certs),
        "signed_30d": month.filter(status=SigningRequest.Status.OK).count(),
        "failed_30d": month.filter(status=SigningRequest.Status.FAILED).count(),
    }
    attention = sorted((c for c in certs if c.status in ("expiring", "expired")), key=lambda c: c.not_after)
    return render(request, "portal/dashboard.html", {
        "stats": stats, "attention": attention, "recent": reqs[:8], "total_certs": len(certs),
    })


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
        "all_users": request.user.has_perm("signing.view_signingrequest"),
    })


@login_required
@permission_required("signing.can_sign", raise_exception=True)
def tokens(request):
    raw = None
    if request.method == "POST":
        name = request.POST.get("name", "").strip()[:255]
        if not name:
            messages.error(request, "Indique uma descrição para o token (ex.: pipeline PAD).")
        else:
            token = SigningToken(user=request.user, name=name)
            raw = token.set_new_token()
            token.save()
    return render(request, "portal/tokens.html", {
        "tokens": SigningToken.objects.filter(user=request.user).order_by("-created_at"),
        "raw_token": raw, "api_url": request.build_absolute_uri(reverse("signing:api_sign")),
    })


@login_required
@require_POST
def revoke_token(request, pk):
    token = get_object_or_404(SigningToken, pk=pk, user=request.user)
    token.is_active = False
    token.save(update_fields=["is_active"])
    messages.success(request, f"Token «{token.name}» revogado.")
    return redirect("portal:tokens")
