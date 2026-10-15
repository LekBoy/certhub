from django.conf import settings
from django.db import models


class PortalPermissions(models.Model):
    """Modelo sem tabela: só serve para declarar as permissões do CertHub (editáveis por grupo na interface)."""

    class Meta:
        managed = False
        default_permissions = ()
        permissions = [
            ("access_certhub", "Aceder ao módulo CertHub"),
            ("manage_modules", "Gerir módulos"),
            ("manage_notifications", "Gerir notificações por e-mail"),
            ("view_all_history", "Ver o histórico de assinaturas de todos"),
            ("view_audit", "Ver o registo de auditoria"),
            ("manage_certificates", "Gerir certificados"),
            ("manage_users", "Gerir utilizadores"),
            ("manage_groups", "Gerir grupos e permissões"),
            ("manage_tokens", "Gerir tokens de todos os utilizadores"),
            ("manage_settings", "Gerir definições do CertHub"),
        ]


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    must_change_password = models.BooleanField(default=False)

    @classmethod
    def for_user(cls, user):
        return cls.objects.get_or_create(user=user)[0]


class AuditEvent(models.Model):
    """Registo de ações administrativas: quem fez o quê."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                             related_name="audit_events")
    username = models.CharField(max_length=150, blank=True)  # fica mesmo se o utilizador for apagado
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=255, blank=True)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]


class ModuleState(models.Model):
    """Módulos desligados pelo administrador. Sem registo = ligado."""

    key = models.CharField(max_length=64, unique=True)
    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)


class NotificationSettings(models.Model):
    """Notificações por e-mail (Outlook / Microsoft 365 / Exchange). Segredos (palavra-passe SMTP, segredo da app
    do Microsoft Graph) NUNCA ficam aqui: ficam em variáveis de ambiente do servidor."""

    class Transport(models.TextChoices):
        SMTP = "smtp", "SMTP (Exchange / Microsoft 365 / relay)"
        GRAPH = "graph", "Microsoft Graph (app registada no Microsoft 365)"

    class Security(models.TextChoices):
        STARTTLS = "starttls", "STARTTLS (porta 587)"
        SSL = "ssl", "SSL/TLS (porta 465)"
        NONE = "none", "Sem cifra (relay interno, porta 25)"

    enabled = models.BooleanField("notificações ativas", default=False)
    recipients = models.TextField("destinatários", blank=True,
                                  help_text="Um e-mail por linha (ou separados por vírgula). Pode ser uma lista de distribuição do Outlook.")
    thresholds = models.CharField("avisar quando faltarem (dias)", max_length=100, default="30,15,7,3,1",
                                  help_text="Separados por vírgula. Cada limiar avisa uma só vez por certificado.")
    notify_expired = models.BooleanField("avisar também quando expirar", default=True)
    base_url = models.CharField("endereço do InfraHub", max_length=255, blank=True,
                                help_text="Para as ligações nos e-mails. Ex.: https://infrahub.empresa.pt")

    from_address = models.EmailField("remetente (e-mail)", blank=True)
    from_name = models.CharField("remetente (nome)", max_length=100, default="InfraHub")
    transport = models.CharField("método de envio", max_length=10, choices=Transport.choices, default=Transport.SMTP)

    smtp_host = models.CharField("servidor SMTP", max_length=255, blank=True,
                                 help_text="Ex.: smtp.office365.com, ou o servidor interno / <empresa>.mail.protection.outlook.com")
    smtp_port = models.PositiveIntegerField("porta", default=587)
    smtp_security = models.CharField("segurança", max_length=10, choices=Security.choices, default=Security.STARTTLS)
    smtp_username = models.CharField("utilizador SMTP", max_length=255, blank=True,
                                     help_text="Vazio = sem autenticação (relay por IP). A palavra-passe vai na variável INFRAHUB_SMTP_PASSWORD.")

    graph_tenant_id = models.CharField("Tenant ID", max_length=64, blank=True)
    graph_client_id = models.CharField("Client ID (ID da aplicação)", max_length=64, blank=True,
                                       help_text="O segredo da aplicação vai na variável INFRAHUB_GRAPH_CLIENT_SECRET.")

    last_run_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_run_summary = models.CharField(max_length=500, blank=True, editable=False)

    class Meta:
        verbose_name = "notificações"

    @classmethod
    def load(cls) -> "NotificationSettings":
        return cls.objects.get_or_create(pk=1)[0]

    @property
    def recipient_list(self) -> list[str]:
        import re

        return [e for e in re.split(r"[\s,;]+", self.recipients) if e]

    @property
    def threshold_list(self) -> list[int]:
        out = set()
        for part in self.thresholds.split(","):
            part = part.strip()
            if part.isdigit() and int(part) > 0:
                out.add(int(part))
        return sorted(out)


class NotificationLog(models.Model):
    """Cada aviso enviado (ou tentado). O par (item, limiar, data de expiração) só avisa uma vez com sucesso."""

    KIND_EXPIRY = "expiry"
    KIND_TEST = "test"

    kind = models.CharField(max_length=10, default=KIND_EXPIRY)
    item_key = models.CharField(max_length=100, blank=True)  # ex.: "inventory:12"
    item_name = models.CharField(max_length=255, blank=True)
    threshold = models.IntegerField(default=0)  # dias; -1 = expirado
    expires_on = models.DateField(null=True, blank=True)
    subject = models.CharField(max_length=255, blank=True)
    recipients = models.TextField(blank=True)
    ok = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["kind", "item_key", "threshold", "expires_on", "ok"])]
