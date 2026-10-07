from django.apps import AppConfig
from django.db.models.signals import post_migrate


def ensure_groups(sender, **kwargs):
    from django.contrib.auth.models import Group, Permission

    groups = {
        "Assinantes": ["can_sign"],  # podem assinar ficheiros e gerir os seus tokens
        "Auditores": ["view_signingrequest", "view_signingcertificate"],  # veem o histórico de todos
    }
    for name, codenames in groups.items():
        group, _ = Group.objects.get_or_create(name=name)
        group.permissions.add(*Permission.objects.filter(content_type__app_label="signing", codename__in=codenames))


class SigningConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "signing"

    def ready(self):
        post_migrate.connect(ensure_groups, sender=self)
