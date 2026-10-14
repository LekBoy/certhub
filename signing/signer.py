"""Assinatura com o Microsoft SignTool (ou comando personalizado). A private key nunca é lida por esta app:
fica no store do Windows, no HSM ou no serviço cloud do fornecedor (ex.: DigiCert KeyLocker)."""
import hashlib
import subprocess
from pathlib import Path

from .models import SigningCertificate, SiteSettings

Method = SigningCertificate.Method


class SigningError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(args: list[str], timeout: int) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
    except FileNotFoundError as exc:
        raise SigningError(f"Programa não encontrado: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SigningError("A assinatura excedeu o tempo limite.") from exc
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        raise SigningError(out[-2000:] or f"O comando saiu com o código {proc.returncode}")
    return out


def _timestamp_args(cert, site) -> list[str]:
    url = cert.timestamp_url or site.timestamp_url
    return ["/tr", url, "/td", "SHA256"] if url else []


def build_command(cert: SigningCertificate, path: str, site: SiteSettings | None = None) -> list[str]:
    """Constrói o comando de assinatura (lista de argumentos, sem shell) conforme o método do certificado."""
    site = site or SiteSettings.load()
    tool = site.signtool_path
    ts = _timestamp_args(cert, site)

    if cert.method == Method.STORE:
        args = [tool, "sign", "/fd", "SHA256", "/sha1", cert.thumbprint, "/s", cert.store_name or "My"]
        if cert.machine_store:
            args.append("/sm")
        return args + ts + [path]

    if cert.method == Method.KEYLOCKER_THUMB:
        # o `smctl windows certsync` instala o certificado no store do utilizador que o corre
        return [tool, "sign", "/sha1", cert.thumbprint, "/fd", "SHA256"] + ts + [path]

    if cert.method == Method.KEYLOCKER_ALIAS:
        if not (cert.csp_name and cert.keypair_alias and cert.cert_file_path):
            raise SigningError("Método KeyLocker por alias requer: provider (KSP), alias da chave e ficheiro .cer.")
        return [tool, "sign", "/csp", cert.csp_name, "/kc", cert.keypair_alias, "/f", cert.cert_file_path,
                "/fd", "SHA256"] + ts + [path]

    if cert.method == Method.CUSTOM:
        values = {
            "signtool": tool, "file": path, "thumbprint": cert.thumbprint, "alias": cert.keypair_alias,
            "csp": cert.csp_name, "cert_file": cert.cert_file_path, "store": cert.store_name,
            "timestamp_url": cert.timestamp_url or site.timestamp_url,
        }
        args = []
        for line in cert.custom_command.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                args.append(line.format_map(values))
            except (KeyError, IndexError, ValueError) as exc:
                raise SigningError(f"Marcador inválido no comando personalizado: {line!r}") from exc
        if not args or "{file}" not in cert.custom_command:
            raise SigningError("O comando personalizado tem de usar {file}.")
        return args

    raise SigningError(f"Método de assinatura desconhecido: {cert.method}")


def verify_enabled(cert: SigningCertificate, site: SiteSettings) -> bool:
    if cert.verify == SigningCertificate.VerifyMode.YES:
        return True
    if cert.verify == SigningCertificate.VerifyMode.NO:
        return False
    return site.verify_after_sign


def sign_file(path: Path, cert: SigningCertificate) -> str:
    """Assina `path` in-place. Devolve o output do comando."""
    site = SiteSettings.load()
    out = _run(build_command(cert, str(path), site), site.timeout_seconds)
    if verify_enabled(cert, site):
        out += "\n" + _run([site.signtool_path, "verify", "/pa", str(path)], site.timeout_seconds)
    return out


def preview_command(cert: SigningCertificate) -> str:
    """Comando que seria executado, para mostrar na interface (com um ficheiro de exemplo)."""
    try:
        return " ".join(f'"{a}"' if " " in a else a for a in build_command(cert, "ficheiro.dll"))
    except SigningError as exc:
        return f"(configuração incompleta: {exc})"
