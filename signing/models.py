import hashlib
import secrets
from datetime import date, timedelta

from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models
from django.utils import timezone

CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"
LIMIT_WARNING_PERCENT = 80


class SiteSettings(models.Model):
    """Definições globais editáveis na interface. Os valores iniciais vêm de config/settings.py (.env).
    Segredos (API keys, palavras-passe) NUNCA ficam aqui: ficam em variáveis de ambiente do servidor."""

    signtool_path = models.CharField("caminho do SignTool", max_length=500)
    timestamp_url = models.CharField("servidor de timestamp (RFC 3161)", max_length=500, blank=True,
                                     help_text="Vazio = assinar sem timestamp (a assinatura deixa de valer quando o certificado expira).")
    verify_after_sign = models.BooleanField("verificar a assinatura depois de assinar", default=True)
    timeout_seconds = models.PositiveIntegerField("tempo limite por assinatura (s)", default=120)
    max_upload_mb = models.PositiveIntegerField("tamanho máximo do ficheiro (MB)", default=100)
    allowed_extensions = models.CharField("extensões permitidas", max_length=500,
                                          help_text="Separadas por vírgula, ex.: .dll, .exe, .msi")
    token_valid_days = models.PositiveIntegerField("validade dos tokens de API (dias)", default=90)
    block_at_limit = models.BooleanField("bloquear assinaturas ao atingir o limite anual", default=False)
    default_groups_version = models.PositiveSmallIntegerField(default=0, editable=False)  # migração das permissões base

    class Meta:
        verbose_name = "definições"

    @classmethod
    def load(cls) -> "SiteSettings":
        obj, _ = cls.objects.get_or_create(pk=1, defaults={
            "signtool_path": settings.SIGNTOOL_PATH,
            "timestamp_url": settings.SIGN_TIMESTAMP_URL,
            "verify_after_sign": settings.SIGN_VERIFY,
            "timeout_seconds": settings.SIGN_TIMEOUT_SECONDS,
            "max_upload_mb": settings.SIGN_MAX_UPLOAD_MB,
            "allowed_extensions": ", ".join(sorted(settings.SIGN_ALLOWED_EXTENSIONS)),
        })
        return obj

    @property
    def extensions(self) -> set[str]:
        out = set()
        for part in self.allowed_extensions.split(","):
            part = part.strip().lower()
            if part:
                out.add(part if part.startswith(".") else "." + part)
        return out


class SigningCertificate(models.Model):
    """Certificado de Code Signing. Só guardamos dados PÚBLICOS: a private key fica no store do servidor
    ou no HSM/cloud do fornecedor (nunca sai de lá)."""

    class Method(models.TextChoices):
        STORE = "store", "Store do Windows (thumbprint)"
        KEYLOCKER_THUMB = "keylocker_thumbprint", "DigiCert KeyLocker: por thumbprint (após certsync)"
        KEYLOCKER_ALIAS = "keylocker_alias", "DigiCert KeyLocker: por alias da chave"
        CUSTOM = "custom", "Comando personalizado"

    class VerifyMode(models.TextChoices):
        DEFAULT = "default", "Seguir a definição global"
        YES = "yes", "Sempre verificar"
        NO = "no", "Nunca verificar"

    name = models.CharField("nome", max_length=255, unique=True)
    thumbprint = models.CharField("thumbprint (SHA-1)", max_length=40, unique=True, editable=False)
    subject = models.CharField(max_length=512, editable=False)
    issuer = models.CharField("emitido por", max_length=512, blank=True, editable=False)
    serial_number = models.CharField("número de série", max_length=80, blank=True, editable=False)
    key_info = models.CharField("chave", max_length=64, blank=True, editable=False)
    source = models.CharField("registado a partir de", max_length=8, blank=True, editable=False)  # cer | pfx
    had_private_key = models.BooleanField("o ficheiro enviado continha a chave privada", default=False, editable=False)
    not_before = models.DateTimeField(editable=False)
    not_after = models.DateTimeField("expira em", editable=False)
    is_active = models.BooleanField("ativo", default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # como assinar
    method = models.CharField("método de assinatura", max_length=30, choices=Method.choices, default=Method.STORE)
    store_name = models.CharField("store", max_length=64, default="My", blank=True)
    machine_store = models.BooleanField("LocalMachine (senão CurrentUser)", default=True)
    keypair_alias = models.CharField("alias da chave (KeyLocker)", max_length=255, blank=True)
    csp_name = models.CharField("nome do provider (KSP)", max_length=255, blank=True,
                                help_text="Ex.: DigiCert Signing Manager KSP. Confirme com: certutil -csp \"...\" -key -user")
    cert_file_path = models.CharField("ficheiro .cer no servidor", max_length=500, blank=True)
    custom_command = models.TextField("comando personalizado", blank=True,
                                      help_text="Um argumento por linha. Marcadores: {signtool} {file} {thumbprint} {alias} {csp} "
                                                "{cert_file} {timestamp_url} {store}")
    timestamp_url = models.CharField("timestamp deste certificado", max_length=500, blank=True,
                                     help_text="Vazio = usar o servidor global.")
    verify = models.CharField("verificar depois de assinar", max_length=10, choices=VerifyMode.choices,
                              default=VerifyMode.DEFAULT)

    # quem pode usar
    allowed_groups = models.ManyToManyField(Group, blank=True, related_name="signing_certificates",
                                            verbose_name="grupos com acesso",
                                            help_text="Vazio = qualquer utilizador com permissão de assinar.")

    # .pfx guardado (cifrado) para descarga controlada por grupos
    pfx_encrypted = models.BinaryField(null=True, blank=True, editable=False)
    pfx_filename = models.CharField(max_length=255, blank=True, editable=False)
    pfx_stored_at = models.DateTimeField(null=True, blank=True, editable=False)
    download_groups = models.ManyToManyField(Group, blank=True, related_name="downloadable_certificates",
                                             verbose_name="grupos que podem descarregar o .pfx",
                                             help_text="Vazio = ninguém (só superadministradores).")

    # subscrição / limites
    annual_limit = models.PositiveIntegerField("limite anual de assinaturas", null=True, blank=True,
                                               help_text="Vazio = sem limite conhecido.")
    subscription_start = models.DateField("início da subscrição", null=True, blank=True)
    renewal_date = models.DateField("data da renovação", null=True, blank=True)
    notes = models.TextField("notas", blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.thumbprint[:8]})"

    # --- validade ---
    @property
    def expired(self):
        return self.not_after <= timezone.now()

    @property
    def usable(self):
        return self.is_active and not self.expired

    @property
    def days_left(self):
        return (self.not_after - timezone.now()).days

    @property
    def status(self):
        """ok | expiring (<= 30 dias) | expired | inactive"""
        if not self.is_active:
            return "inactive"
        if self.expired:
            return "expired"
        return "expiring" if self.days_left <= 30 else "ok"

    # --- subscrição e limites ---
    @property
    def period_start(self) -> date:
        """Início do período de contagem: o último aniversário da subscrição (ou 1 de janeiro)."""
        today = timezone.localdate()
        start = self.subscription_start
        if not start:
            return date(today.year, 1, 1)
        try:
            anniversary = start.replace(year=today.year)
        except ValueError:  # 29 de fevereiro
            anniversary = date(today.year, 3, 1)
        return anniversary if anniversary <= today else anniversary.replace(year=today.year - 1)

    @property
    def signed_in_period(self) -> int:
        return self.requests.filter(status="ok", created_at__date__gte=self.period_start).count()

    @property
    def usage_percent(self):
        if not self.annual_limit:
            return None
        return int(self.signed_in_period * 100 / self.annual_limit)

    @property
    def limit_status(self):
        """none | ok | warning (>= 80%) | reached"""
        pct = self.usage_percent
        if pct is None:
            return "none"
        if pct >= 100:
            return "reached"
        return "warning" if pct >= LIMIT_WARNING_PERCENT else "ok"

    @property
    def renewal_days(self):
        return (self.renewal_date - timezone.localdate()).days if self.renewal_date else None

    @property
    def renewal_soon(self):
        d = self.renewal_days
        return d is not None and d <= 30

    @property
    def attention(self) -> list[str]:
        """Motivos para aparecer em «Requer atenção» no painel."""
        out = []
        if self.status == "expired":
            out.append("Certificado expirado")
        elif self.status == "expiring":
            out.append(f"Expira em {self.days_left} dias")
        if self.limit_status == "reached":
            out.append("Limite anual atingido")
        elif self.limit_status == "warning":
            out.append(f"{self.usage_percent}% do limite anual")
        if self.is_active and self.renewal_soon:
            d = self.renewal_days
            out.append("Renovação passada" if d < 0 else f"Renovação em {d} dias")
        return out

    def usable_by(self, user) -> bool:
        if not self.usable:
            return False
        if user.is_superuser or not self.allowed_groups.exists():
            return True
        return self.allowed_groups.filter(pk__in=user.groups.values_list("pk", flat=True)).exists()

    @property
    def has_pfx(self) -> bool:
        return bool(self.pfx_encrypted)

    def can_download(self, user) -> bool:
        """.pfx guardado + permissão do módulo + (superadmin ou grupo escolhido neste certificado)."""
        if not (self.has_pfx and self.is_active and user.is_authenticated and user.is_active):
            return False
        if not user.has_perm("signing.download_pfx"):
            return False
        if user.is_superuser:
            return True
        return self.download_groups.filter(pk__in=user.groups.values_list("pk", flat=True)).exists()

    @classmethod
    def usable_for(cls, user):
        return [c for c in cls.objects.filter(is_active=True, not_after__gt=timezone.now()).order_by("-not_after")
                if c.usable_by(user)]


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

    def set_new_token(self, valid_days: int = 90, expires_at=None) -> str:
        """Devolve o token em claro; só o hash é guardado. Quem chama faz save().
        `expires_at` (datetime) tem prioridade sobre `valid_days`."""
        raw = secrets.token_urlsafe(32)
        self.token_hash = self.hash_token(raw)
        self.token_prefix = raw[:8]
        self.expires_at = expires_at or timezone.now() + timedelta(days=valid_days)
        return raw

    @property
    def valid(self):
        return self.is_active and self.expires_at > timezone.now()

    @property
    def days_left(self) -> int:
        """Dias completos que faltam (0 = expira hoje)."""
        return max((timezone.localtime(self.expires_at).date() - timezone.localdate()).days, 0)


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
        permissions = [("can_sign", "Pode assinar ficheiros"),
                       ("download_pfx", "Pode descarregar o .pfx de certificados")]

    def __str__(self):
        return f"{self.filename} [{self.status}]"
