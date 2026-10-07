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