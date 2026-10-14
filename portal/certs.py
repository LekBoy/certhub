"""Gestão de certificados dentro do CertHub."""
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from signing import service, signer
from signing.models import SigningCertificate

from .audit import audit
from .forms import CertificateForm
from .permissions import perm_required


def _after_upload_notice(request, cert, form):
    if form.parsed and form.parsed["source"] == "pfx":
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
              f"thumbprint {cert.thumbprint}; método {cert.method}; origem {cert.source}")
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
