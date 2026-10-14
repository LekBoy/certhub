import tempfile
from pathlib import Path

from . import signer
from .models import SigningCertificate, SigningRequest, SiteSettings


class RejectedUpload(Exception):
    pass


class LimitReached(RejectedUpload):
    pass


def validate_upload(uploaded, site: SiteSettings):
    name = Path(uploaded.name).name
    if Path(name).suffix.lower() not in site.extensions:
        raise RejectedUpload(f"Extensão não permitida. Permitidas: {', '.join(sorted(site.extensions))}")
    if uploaded.size > site.max_upload_mb * 1024 * 1024:
        raise RejectedUpload(f"Ficheiro excede {site.max_upload_mb} MB.")
    return name


def sign_upload(uploaded, user, certificate: SigningCertificate, via_api: bool):
    """Assina o ficheiro e devolve (nome, bytes assinados, sha256). Regista sempre auditoria."""
    site = SiteSettings.load()
    if not certificate.usable_by(user):
        raise RejectedUpload("Não tem acesso a este certificado, ou o certificado não está válido.")
    if site.block_at_limit and certificate.limit_status == "reached":
        raise LimitReached("O limite anual de assinaturas deste certificado foi atingido.")
    name = validate_upload(uploaded, site)
    with tempfile.TemporaryDirectory(prefix="certhub-sign-") as tmp:
        path = Path(tmp) / name
        with open(path, "wb") as f:
            for chunk in uploaded.chunks():
                f.write(chunk)
        record = SigningRequest(
            user=user, certificate=certificate, filename=name, size=uploaded.size,
            sha256_original=signer.sha256_file(path), via_api=via_api,
        )
        try:
            signer.sign_file(path, certificate)
        except signer.SigningError as exc:
            record.status, record.error = SigningRequest.Status.FAILED, str(exc)
            record.save()
            raise
        record.sha256_signed = signer.sha256_file(path)
        record.status = SigningRequest.Status.OK
        record.save()
        return name, path.read_bytes(), record.sha256_signed


def test_signing(certificate: SigningCertificate) -> str:
    """Assina um ficheiro de teste descartável. Não conta para o limite nem entra no histórico."""
    with tempfile.TemporaryDirectory(prefix="certhub-test-") as tmp:
        path = Path(tmp) / "certhub-test.ps1"
        path.write_text("Write-Output 'certhub test'\n")
        return signer.sign_file(path, certificate) or "OK"
