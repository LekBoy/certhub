import hashlib
import secrets
from datetime import timedelta

from django.db import models
from django.utils import timezone


class Host(models.Model):
    class OS(models.TextChoices):
        LINUX = "linux", "Linux"
        WINDOWS = "windows", "Windows"
        OTHER = "other", "Outro"

    class Environment(models.TextChoices):
        PRODUCTION = "prod", "Produção"
        STAGING = "staging", "Teste"
        DEV = "dev", "Desenvolvimento"

    name = models.CharField("nome", max_length=255, unique=True)
    ip_address = models.GenericIPAddressField("IP", null=True, blank=True)
    os = models.CharField(max_length=20, choices=OS.choices, default=OS.OTHER)
    environment = models.CharField(max_length=20, choices=Environment.choices, default=Environment.PRODUCTION)
    owner = models.CharField("responsável", max_length=255, blank=True)
    is_active = models.BooleanField("ativo", default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    token_hash = models.CharField(max_length=64, unique=True, blank=True, editable=False)
    token_prefix = models.CharField(max_length=8, blank=True, editable=False)
    token_expires_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def is_authenticated(self):  # permite usar o Host como request.user na API
        return True

    @property
    def token_expired(self):
        return self.token_expires_at is not None and self.token_expires_at <= timezone.now()

    @staticmethod
    def hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def set_new_token(self, valid_days: int = 90) -> str:
        """Gera um token novo, guarda o hash e devolve o token em claro.
        Quem chama tem de fazer save() e mostrar o token uma só vez."""
        raw = secrets.token_urlsafe(32)
        self.token_hash = self.hash_token(raw)
        self.token_prefix = raw[:8]
        self.token_expires_at = timezone.now() + timedelta(days=valid_days)
        return raw

ALERT_DAYS = 30


class InventoryCertificate(models.Model):
    """Certificado carregado só para inventário. Guardamos INFORMAÇÃO: nunca o ficheiro, a chave nem a palavra-passe."""

    class Type(models.TextChoices):
        TLS = "tls", "Servidor TLS/SSL"
        CODE_SIGNING = "code_signing", "Code Signing"
        CLIENT = "client", "Cliente"
        EMAIL = "email", "E-mail (S/MIME)"
        CA = "ca", "Autoridade certificadora"
        OTHER = "other", "Outro"

    # dados lidos do certificado
    name = models.CharField("nome", max_length=255)
    common_name = models.CharField(max_length=255, blank=True, editable=False)
    subject = models.CharField(max_length=512, editable=False)
    issuer = models.CharField("emitido por", max_length=512, editable=False)
    serial_number = models.CharField("número de série", max_length=80, editable=False)
    sha1 = models.CharField("SHA-1", max_length=40, editable=False)
    sha256 = models.CharField("SHA-256", max_length=64, unique=True, editable=False)
    not_before = models.DateTimeField(editable=False)
    not_after = models.DateTimeField("expira em", editable=False)
    key_info = models.CharField("chave", max_length=64, blank=True, editable=False)
    signature_algorithm = models.CharField("algoritmo de assinatura", max_length=64, blank=True, editable=False)
    san = models.TextField("nomes alternativos (SAN)", blank=True, editable=False)
    extended_key_usage = models.TextField("utilizações avançadas", blank=True, editable=False)
    key_usage = models.TextField("utilizações da chave", blank=True, editable=False)
    is_ca = models.BooleanField(default=False, editable=False)
    is_wildcard = models.BooleanField(default=False, editable=False)
    cert_type = models.CharField("tipo", max_length=20, choices=Type.choices, default=Type.OTHER, editable=False)

    # origem do upload
    source_filename = models.CharField("ficheiro de origem", max_length=255, blank=True, editable=False)
    source_format = models.CharField(max_length=8, blank=True, editable=False)  # pfx | pem | der | p7b
    had_private_key = models.BooleanField("o ficheiro continha a chave privada", default=False, editable=False)
    uploaded_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="inventory_uploads", editable=False)

    # dados geridos por pessoas
    server = models.CharField("servidor / local", max_length=255, blank=True)
    owner = models.CharField("responsável", max_length=255, blank=True)
    purpose = models.CharField("utilização", max_length=255, blank=True)
    notes = models.TextField("notas", blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["not_after"]
        permissions = [("manage_inventory", "Gerir o inventário de certificados")]

    def __str__(self):
        return self.name

    @property
    def san_list(self):
        return [x for x in self.san.splitlines() if x]

    @property
    def eku_list(self):
        return [x for x in self.extended_key_usage.splitlines() if x]

    @property
    def ku_list(self):
        return [x for x in self.key_usage.splitlines() if x]

    @property
    def days_left(self):
        return (self.not_after - timezone.now()).days

    @property
    def status(self):
        """ok | expiring (<= 30 dias) | expired"""
        if self.not_after <= timezone.now():
            return "expired"
        return "expiring" if self.days_left <= ALERT_DAYS else "ok"
