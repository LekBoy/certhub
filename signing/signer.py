"""Assinatura com o Microsoft SignTool. A private key nunca é lida por esta app:
o SignTool usa o certificado do Windows certificate store (/sha1 <thumbprint>)."""
import hashlib
import subprocess
from pathlib import Path

from django.conf import settings


class SigningError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(args: list[str]) -> None:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=settings.SIGN_TIMEOUT_SECONDS, shell=False
        )
    except FileNotFoundError as exc:
        raise SigningError(f"SignTool não encontrado: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SigningError("SignTool excedeu o tempo limite.") from exc
    if proc.returncode != 0:
        raise SigningError((proc.stdout + proc.stderr).strip()[-2000:] or f"SignTool saiu com {proc.returncode}")


def sign_file(path: Path, certificate) -> None:
    """Assina `path` in-place (SHA-256 + timestamp RFC 3161 SHA-256)."""
    args = [
        settings.SIGNTOOL_PATH, "sign",
        "/fd", "SHA256",
        "/tr", settings.SIGN_TIMESTAMP_URL, "/td", "SHA256",
        "/sha1", certificate.thumbprint,
        "/s", certificate.store_name,
    ]
    if certificate.machine_store:
        args.append("/sm")
    args.append(str(path))
    _run(args)
    if settings.SIGN_VERIFY:
        _run([settings.SIGNTOOL_PATH, "verify", "/pa", str(path)])
