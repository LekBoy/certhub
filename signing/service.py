import tempfile
from pathlib import Path

from django.conf import settings

from . import signer
from .models import SigningCertificate, SigningRequest


class RejectedUpload(Exception):
    pass


def validate_upload(uploaded):
    name = Path(uploaded.name).name
    if Path(name).suffix.lower() not in settings.SIGN_ALLOWED_EXTENSIONS:
        raise RejectedUpload(f"Extensão não permitida. Permitidas: {', '.join(sorted(settings.SIGN_ALLOWED_EXTENSIONS))}")
    if uploaded.size > settings.SIGN_MAX_UPLOAD_MB * 1024 * 1024:
        raise RejectedUpload(f"Ficheiro excede {settings.SIGN_MAX_UPLOAD_MB} MB.")
    return name


def sign_upload(uploaded, user, certificate: SigningCertificate, via_api: bool):
    """Assina o ficheiro e devolve (nome, bytes assinados). Regista sempre auditoria."""
    name = validate_upload(uploaded)
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
