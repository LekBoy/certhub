from django.contrib.auth.backends import ModelBackend

from . import modules


class ModuleAccessBackend(ModelBackend):
    """As permissões de um módulo só valem com o acesso a esse módulo (e com o módulo ligado)."""

    def has_perm(self, user_obj, perm, obj=None):
        if not super().has_perm(user_obj, perm, obj):
            return False
        module = modules.module_for_permission(perm)
        if module is None:
            return True
        if not modules.is_enabled(module, user_obj):
            return False
        return perm == module.access_perm or super().has_perm(user_obj, module.access_perm)
