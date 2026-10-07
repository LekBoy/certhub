from django.conf import settings
from django.contrib.auth.decorators import login_required, permission_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import SigningCertificate, SigningToken
from .service import RejectedUpload, sign_upload
from .signer import SigningError


def _download(name, content, digest):
    resp = HttpResponse(content, content_type="application/octet-stream")
    resp["Content-Disposition"] = f'attachment; filename="{name}"'
    resp["X-Signed-SHA256"] = digest
    return resp


@login_required
@permission_required("signing.can_sign", raise_exception=True)
def sign_page(request):
    certs = SigningCertificate.objects.filter(is_active=True, not_after__gt=timezone.now()).order_by("-not_after")
    error = None
    if request.method == "POST":
        uploaded = request.FILES.get("file")
        cert = certs.filter(pk=request.POST.get("certificate") or 0).first()
        if not uploaded or not cert:
            error = "Escolha um ficheiro e um certificado válido."
        else:
            try:
                return _download(*sign_upload(uploaded, request.user, cert, via_api=False))
            except (RejectedUpload, SigningError) as exc:
                error = str(exc)
        if request.headers.get("X-Requested-With") == "fetch":
            return JsonResponse({"error": error}, status=400)
    return render(request, "signing/sign.html", {
        "certificates": certs, "error": error,
        "allowed_extensions": sorted(settings.SIGN_ALLOWED_EXTENSIONS), "max_mb": settings.SIGN_MAX_UPLOAD_MB,
    })


def _token_user(request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = SigningToken.objects.select_related("user").filter(
        token_hash=SigningToken.hash_token(header[7:].strip())
    ).first()
    if not token or not token.valid or not token.user.is_active or not token.user.has_perm("signing.can_sign"):
        return None
    token.last_used = timezone.now()
    token.save(update_fields=["last_used"])
    return token.user


@csrf_exempt
@require_POST
def sign_api(request):
    """curl -H "Authorization: Bearer <token>" -F file=@Foo.dll [-F certificate=<id>] -o Foo.signed.dll URL"""
    user = _token_user(request)
    if user is None:
        return JsonResponse({"error": "Token inválido, expirado ou sem permissão."}, status=401)
    uploaded = request.FILES.get("file")
    if not uploaded:
        return JsonResponse({"error": "Campo multipart 'file' em falta."}, status=400)
    certs = SigningCertificate.objects.filter(is_active=True, not_after__gt=timezone.now())
    cert = certs.filter(pk=request.POST["certificate"]).first() if request.POST.get("certificate", "").isdigit() \
        else (certs.first() if certs.count() == 1 else None)
    if cert is None:
        return JsonResponse({"error": "Indique 'certificate' (id) válido."}, status=400)
    try:
        return _download(*sign_upload(uploaded, user, cert, via_api=True))
    except RejectedUpload as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except SigningError as exc:
        return JsonResponse({"error": f"Falha na assinatura: {exc}"}, status=500)
