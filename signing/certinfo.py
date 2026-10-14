"""Leitura/validação de certificados com `cryptography`: .cer/.crt/.pem (só a parte pública) e .pfx/.p12.
Do .pfx só se lê informação: o ficheiro e a palavra-passe nunca são guardados."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import CODE_SIGNING_OID


class CertificateError(ValueError):
    pass


def _key_info(cert) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size} bits"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return type(key).__name__.replace("PublicKey", "")
    return type(key).__name__


def describe(cert: x509.Certificate) -> dict:
    """Dados do certificado; recusa se não tiver o EKU Code Signing."""
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = []
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise CertificateError(f"O certificado não tem a utilização Code Signing ({CODE_SIGNING_OID}).")
    return {
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303 - é o formato que o SignTool usa
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "X"),
        "key_info": _key_info(cert),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
    }


def parse_public_certificate(data: bytes) -> dict:
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise CertificateError("Ficheiro não é um certificado X.509 (.cer/.crt/.pem).") from exc
    return {**describe(cert), "source": "cer", "had_private_key": False}


def parse_pkcs12(data: bytes, password: str | None) -> dict:
    """Lê um .pfx/.p12 em memória. Devolve os dados do certificado; a chave privada é ignorada e descartada."""
    try:
        bundle = pkcs12.load_pkcs12(data, password.encode() if password else None)
    except ValueError as exc:
        raise CertificateError("Não foi possível abrir o .pfx: palavra-passe incorreta ou ficheiro inválido.") from exc
    certs = ([bundle.cert.certificate] if bundle.cert else []) + [c.certificate for c in bundle.additional_certs]
    if not certs:
        raise CertificateError("O .pfx não contém nenhum certificado.")

    def is_code_signing(c):
        try:
            return ExtendedKeyUsageOID.CODE_SIGNING in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            return False

    # o certificado de assinatura é o do par de chaves; sem chave, o primeiro com Code Signing
    leaf = certs[0] if bundle.cert else next((c for c in certs if is_code_signing(c)), certs[0])
    info = describe(leaf)
    info.update(source="pfx", had_private_key=bundle.key is not None)
    info["chain_length"] = len(certs) - 1
    return info
