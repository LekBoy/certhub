from django.conf import settings
from django.db import models


class PortalPermissions(models.Model):
    """Modelo sem tabela: só serve para declarar as permissões do CertHub (editáveis por grupo na interface)."""

    class Meta:
        managed = False
        default_permissions = ()
        permissions = [
            ("view_all_history", "Ver o histórico de assinaturas de todos"),
            ("view_audit", "Ver o registo de auditoria"),
            ("manage_certificates", "Gerir certificados"),
            ("manage_users", "Gerir utilizadores"),
            ("manage_groups", "Gerir grupos e permissões"),
            ("manage_tokens", "Gerir tokens de todos os utilizadores"),
            ("manage_settings", "Gerir definições da plataforma"),
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
