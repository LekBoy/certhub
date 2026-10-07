import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"


class SigningCertificate(models.Model):
    """Certificado de Code Signing. Só guardamos dados PÚBLICOS: a private key
    fica no certificate store do servidor de assinatura (nunca sai de lá)."""

    name = models.CharField("nome", max_length=255, unique=True)
    thumbprint = models.CharField("thumbprint (SHA-1)", max_length=40, unique=True, editable=False)
    subject = models.CharField(max_length=512, editable=False)
    not_before = models.DateTimeField(editable=False)
    not_after = models.DateTimeField("expira em", editable=False)
    store_name = models.CharField("store", max_length=64, default="My")
    machine_store = models.BooleanField("LocalMachine (senão CurrentUser)", default=True)
    is_active = models.BooleanField("ativo", default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.thumbprint[:8]})"

    @property
    def expired(self):
        return self.not_after <= timezone.now()

    @property
    def usable(self):
        return self.is_active and not self.expired


class SigningToken(models.Model):
    """Token de API (Bearer) para pipelines de build chamarem /api/sign/."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="signing_tokens")
    name = models.CharField("descrição", max_length=255)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    token_prefix = models.CharField(max_length=8, editable=False)
    expires_at = models.DateTimeField(editable=False)
    is_active = models.BooleanField("ativo", default=True)
    last_used = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.token_prefix}…)"

    @staticmethod
    def hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def set_new_token(self, valid_days: int = 90) -> str:
        """Devolve o token em claro; só o hash é guardado. Quem chama faz save()."""
        raw = secrets.token_urlsafe(32)
        self.token_hash = self.hash_token(raw)
        self.token_prefix = raw[:8]
        self.expires_at = timezone.now() + timedelta(days=valid_days)
        return raw

    @property
    def valid(self):
        return self.is_active and self.expires_at > timezone.now()


class SigningRequest(models.Model):
    """Registo de auditoria: quem assinou o quê, com que certificado."""

    class Status(models.TextChoices):
        OK = "ok", "Assinado"
        FAILED = "failed", "Falhou"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="signing_requests")
    certificate = models.ForeignKey(SigningCertificate, on_delete=models.PROTECT, related_name="requests")
    filename = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    sha256_original = models.CharField(max_length=64)
    sha256_signed = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices)
    error = models.TextField(blank=True)
    via_api = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        permissions = [("can_sign", "Pode assinar ficheiros")]

    def __str__(self):
        return f"{self.filename} [{self.status}]"
