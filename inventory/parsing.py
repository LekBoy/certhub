"""Leitura de certificados para o inventário: PEM (um ou vários), DER (.cer/.crt), PKCS#7 (.p7b) e PKCS#12 (.pfx/.p12).
Tudo em memória: chaves privadas e palavras-passe nunca são guardadas."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from signing.certinfo import _key_info

from .models import InventoryCertificate

Type = InventoryCertificate.Type

EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "Servidor TLS",
    ExtendedKeyUsageOID.CLIENT_AUTH: "Cliente TLS",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail (S/MIME)",
    ExtendedKeyUsageOID.TIME_STAMPING: "Timestamp",
    ExtendedKeyUsageOID.OCSP_SIGNING: "Assinatura OCSP",
}
KU_FLAGS = [("digital_signature", "Assinatura digital"), ("content_commitment", "Não repúdio"),
            ("key_encipherment", "Cifra de chaves"), ("data_encipherment", "Cifra de dados"),
            ("key_agreement", "Acordo de chaves"), ("key_cert_sign", "Assinar certificados"),
            ("crl_sign", "Assinar CRL")]


class ParseError(ValueError):
    pass


class PasswordNeeded(ParseError):
    pass


def _ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def describe(cert: x509.Certificate) -> dict:
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else ""
    san_ext = _ext(cert, x509.SubjectAlternativeName)
    san = []
    if san_ext:
        san = list(san_ext.get_values_for_type(x509.DNSName)) + [str(i) for i in san_ext.get_values_for_type(x509.IPAddress)]
    eku_ext = _ext(cert, x509.ExtendedKeyUsage)
    eku_oids = list(eku_ext) if eku_ext else []
    ku_ext = _ext(cert, x509.KeyUsage)
    ku = []
    if ku_ext:
        ku = [label for attr, label in KU_FLAGS if getattr(ku_ext, attr, False)]
    bc = _ext(cert, x509.BasicConstraints)
    is_ca = bool(bc and bc.ca)
    wildcard = common_name.startswith("*.") or any(n.startswith("*.") for n in san)

    if is_ca:
        kind = Type.CA
    elif ExtendedKeyUsageOID.CODE_SIGNING in eku_oids:
        kind = Type.CODE_SIGNING
    elif ExtendedKeyUsageOID.SERVER_AUTH in eku_oids or (san and not eku_oids):
        kind = Type.TLS
    elif ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids:
        kind = Type.CLIENT
    elif ExtendedKeyUsageOID.EMAIL_PROTECTION in eku_oids:
        kind = Type.EMAIL
    else:
        kind = Type.OTHER

    try:
        sig = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    except Exception:  # noqa: BLE001
        sig = ""
    return {
        "name": common_name or cert.subject.rfc4514_string()[:255],
        "common_name": common_name,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "X"),
        "sha1": cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303 - formato usado pelo Windows
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "key_info": _key_info(cert),
        "signature_algorithm": sig,
        "san": "\n".join(san),
        "extended_key_usage": "\n".join(EKU_NAMES.get(o, o.dotted_string) for o in eku_oids),
        "key_usage": "\n".join(ku),
        "is_ca": is_ca,
        "is_wildcard": wildcard,
        "cert_type": kind,
    }


def load_certificates(filename: str, data: bytes, password: str | None):
    """Devolve (certificados, had_private_key, formato)."""
    if b"-----BEGIN" in data:
        has_key = b"PRIVATE KEY-----" in data
        try:
            certs = x509.load_pem_x509_certificates(data)
            return certs, has_key, "pem"
        except ValueError:
            pass
        try:
            return pkcs7.load_pem_pkcs7_certificates(data), has_key, "p7b"
        except ValueError:
            pass
        if has_key:
            raise ParseError("O ficheiro só contém uma chave privada e nenhum certificado. A chave não é lida nem guardada.")
        raise ParseError("Não foi encontrado nenhum certificado no ficheiro PEM.")

    try:
        return [x509.load_der_x509_certificate(data)], False, "der"
    except ValueError:
        pass
    try:
        return pkcs7.load_der_pkcs7_certificates(data), False, "p7b"
    except ValueError:
        pass
    try:
        bundle = pkcs12.load_pkcs12(data, password.encode() if password else None)
    except ValueError as exc:
        if filename.lower().endswith((".pfx", ".p12")) or data[:1] == b"\x30":
            if not password:
                raise PasswordNeeded("O ficheiro parece um .pfx protegido: indique a palavra-passe.") from exc
            raise ParseError("Palavra-passe incorreta, ou o ficheiro não é um .pfx válido.") from exc
        raise ParseError("Formato não reconhecido (esperado .pfx, .crt, .cer, .pem ou .p7b).") from exc
    certs = ([bundle.cert.certificate] if bundle.cert else []) + [c.certificate for c in bundle.additional_certs]
    if not certs:
        raise ParseError("O .pfx não contém certificados.")
    return certs, bundle.key is not None, "pfx"
