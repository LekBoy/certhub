"""Leitura/validação do certificado PÚBLICO (.cer/.crt/.pem) com `cryptography`."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import CODE_SIGNING_OID


class CertificateError(ValueError):
    pass


def parse_public_certificate(data: bytes) -> dict:
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise CertificateError("Ficheiro não é um certificado X.509 (.cer/.crt/.pem).") from exc

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = []
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise CertificateError(f"O certificado não tem a utilização Code Signing ({CODE_SIGNING_OID}).")

    return {
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303 - é o formato que o SignTool usa
        "subject": cert.subject.rfc4514_string(),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
    }
