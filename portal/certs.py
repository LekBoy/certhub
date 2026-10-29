"""Gestão de certificados dentro do CertHub."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from signing import filecrypt, service, signer
from signing.models import SigningCertificate

from .audit import audit
from .forms import CertificateForm
from .permissions import perm_required


def _after_upload_notice(request, cert, form):
    if form.parsed and form.parsed["source"] == "pfx":
        if form.cleaned_data.get("store_pfx"):
            msg = ("O .pfx foi guardado cifrado. A palavra-passe NÃO é guardada: entregue-a a quem o descarregar "
                   "por outro canal.")
        else:
            msg = "O ficheiro .pfx e a palavra-passe foram usados só para ler os dados e não foram guardados."
            if form.parsed["had_private_key"]:
                msg += " O .pfx continha a chave privada: apague as cópias que não forem necessárias."
        messages.info(request, msg)


def _ctx(form, cert, **extra):
    return {"form": form, "cert": cert, "preview": signer.preview_command(cert) if cert else "", **extra}


@perm_required("portal.manage_certificates")
def certificate_create(request):
    form = CertificateForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        cert = form.save()
        audit(request, "certificate_created", cert.name,
              f"thumbprint {cert.thumbprint}; método {cert.method}; origem {cert.source}"
              + ("; .pfx guardado para download" if cert.has_pfx else ""))
        _after_upload_notice(request, cert, form)
        messages.success(request, f"Certificado «{cert.name}» registado. Use «Testar assinatura» para validar.")
        return redirect("portal:certificate_edit", pk=cert.pk)
    return render(request, "portal/certificate_form.html", _ctx(form, None))


@perm_required("portal.manage_certificates")
def certificate_edit(request, pk):
    cert = get_object_or_404(SigningCertificate, pk=pk)
    form = CertificateForm(request.POST or None, request.FILES or None, instance=cert)
    if request.method == "POST" and form.is_valid():
        cert = form.save()
        audit(request, "certificate_updated", cert.name,
              ", ".join(sorted(f for f in form.changed_data if f != "pfx_password")))
        _after_upload_notice(request, cert, form)
        messages.success(request, "Certificado atualizado.")
        return redirect("portal:certificate_edit", pk=cert.pk)
    return render(request, "portal/certificate_form.html", _ctx(form, cert))


@perm_required("portal.manage_certificates")
@require_POST
def certificate_test(request, pk):
    cert = get_object_or_404(SigningCertificate, pk=pk)
    try:
        output = service.test_signing(cert)
        ok = True
        audit(request, "certificate_tested", cert.name, "OK")
    except signer.SigningError as exc:
        output, ok = str(exc), False
        audit(request, "certificate_tested", cert.name, f"FALHOU: {exc}"[:500])
    return render(request, "portal/certificate_form.html",
                  _ctx(CertificateForm(instance=cert), cert, test_output=output, test_ok=ok))


@perm_required("portal.manage_certificates")
@require_POST
def certificate_delete(request, pk):
    cert = get_object_or_404(SigningCertificate, pk=pk)
    if cert.requests.exists():
        messages.error(request, "Este certificado tem histórico de assinaturas e não pode ser apagado. Desative-o.")
        return redirect("portal:certificate_edit", pk=pk)
    name = cert.name
    cert.delete()
    audit(request, "certificate_deleted", name)
    messages.success(request, f"Certificado «{name}» apagado.")
    return redirect("portal:certificates")


@login_required
@require_POST
def certificate_download(request, pk):
    """Descarrega o .pfx guardado: só com a permissão do módulo e o grupo escolhido no certificado. Fica auditado."""
    cert = get_object_or_404(SigningCertificate, pk=pk)
    if not cert.can_download(request.user):
        audit(request, "certificate_pfx_download_denied", cert.name)
        return HttpResponse("Sem permissão para descarregar este ficheiro.", status=403)
    try:
        data = filecrypt.decrypt(cert.pfx_encrypted)
    except filecrypt.FileCryptError as exc:
        messages.error(request, str(exc))
        return redirect("portal:certificates")
    audit(request, "certificate_pfx_downloaded", cert.name, f"thumbprint {cert.thumbprint}")
    response = HttpResponse(data, content_type="application/x-pkcs12")
    response["Content-Disposition"] = f'attachment; filename="{cert.pfx_filename or "certificado.pfx"}"'
    response["Cache-Control"] = "no-store"
    return response
