"""Cifra de ficheiros guardados (ex.: .pfx para download). A chave vive só no ambiente do servidor.

INFRAHUB_FILE_KEY = uma ou mais chaves Fernet separadas por vírgula (a primeira cifra; todas decifram,
para permitir rodar a chave). Gerar:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

ENV_VAR = "INFRAHUB_FILE_KEY"


class FileCryptError(Exception):
    pass


def _fernet() -> MultiFernet:
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        raise FileCryptError(f"A variável {ENV_VAR} não está definida no servidor.")
    try:
        return MultiFernet([Fernet(k.strip().encode()) for k in raw.split(",") if k.strip()])
    except (ValueError, TypeError) as exc:
        raise FileCryptError(f"A variável {ENV_VAR} não tem uma chave Fernet válida.") from exc


def is_configured() -> bool:
    try:
        _fernet()
        return True
    except FileCryptError:
        return False


def encrypt(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt(token: bytes) -> bytes:
    try:
        return _fernet().decrypt(bytes(token))
    except InvalidToken as exc:
        raise FileCryptError("Não foi possível decifrar o ficheiro (chave diferente da usada ao guardar?).") from exc
