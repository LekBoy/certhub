from django.apps import AppConfig
from django.db.models.signals import post_migrate


class PortalConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "portal"

    def ready(self):
        from .certhub_module import register_all
        from .permissions import ensure_default_groups

        register_all()
        post_migrate.connect(ensure_default_groups, sender=self)
