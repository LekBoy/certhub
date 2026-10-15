from functools import wraps

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import PermissionDenied

from . import modules

# Permissões da plataforma (os módulos declaram as suas em portal/modules.py)
PLATFORM_PERMISSION_GROUPS = [
    ("Plataforma", [
        ("portal.manage_users", "Gerir utilizadores", "Criar, editar, desativar e repor palavras-passe."),
        ("portal.manage_groups", "Gerir grupos", "Criar grupos e escolher o acesso a módulos e as permissões."),
        ("portal.manage_modules", "Gerir módulos", "Ver os módulos e ligar ou desligar cada um."),
        ("portal.manage_notifications", "Gerir notificações", "Avisos por e-mail de certificados a expirar."),
        ("portal.view_audit", "Ver a auditoria", "Registo de ações administrativas."),
    ]),
]
PLATFORM_PERMISSIONS = [code for _, items in PLATFORM_PERMISSION_GROUPS for code, _, _ in items]


def all_permission_codes() -> list[str]:
    return PLATFORM_PERMISSIONS + [c for m in modules.all_modules() for c in m.all_codes]


def default_groups() -> dict[str, list[str]]:
    certhub = modules.get("certhub")
    return {
        "Assinantes": [certhub.access_perm, "signing.can_sign"],
        "Auditores": [certhub.access_perm, "portal.view_all_history", "portal.view_audit",
                      "inventory.view_inventorycertificate"],
        "Administradores": all_permission_codes(),
    }


DEFAULT_GROUPS_VERSION = 4
# permissões acrescentadas em cada versão: os grupos base existentes só recebem as novas, nunca perdem nenhuma
NEW_BY_VERSION = {
    2: {"inventory.view_inventorycertificate", "inventory.manage_inventory"},
    3: {"portal.access_certhub", "portal.manage_modules"},
    4: {"portal.manage_notifications"},
}


def permission_objects(codes):
    ids = []
    for code in codes:
        app, codename = code.split(".")
        ids.append(Permission.objects.get(content_type__app_label=app, codename=codename).pk)
    return Permission.objects.filter(pk__in=ids)


def ensure_default_groups(sender=None, **kwargs):
    """post_migrate: cria as permissões e os grupos base, e atualiza instalações anteriores sem retirar nada."""
    from django.apps import apps

    from signing.models import SiteSettings

    for label in ("signing", "portal", "inventory"):
        create_permissions(apps.get_app_config(label), verbosity=0)
    _sync_permission_names()

    site = SiteSettings.load()
    old = site.default_groups_version
    groups = default_groups()
    for name, codes in groups.items():
        group, created = Group.objects.get_or_create(name=name)
        if created:
            group.permissions.set(permission_objects(codes))
        elif old < DEFAULT_GROUPS_VERSION:
            new = {c for v, cs in NEW_BY_VERSION.items() if v > old for c in cs}
            group.permissions.add(*permission_objects([c for c in codes if c in new]))
    if old < 3:
        _grant_access_to_existing_module_users()
    if old < DEFAULT_GROUPS_VERSION:
        site.default_groups_version = DEFAULT_GROUPS_VERSION
        site.save(update_fields=["default_groups_version"])


def _grant_access_to_existing_module_users():
    """Versão 3: o acesso ao módulo passou a ser obrigatório. Quem já tinha permissões de um módulo
    (por grupo ou diretamente) recebe o acesso, para ninguém perder o que tinha."""
    from django.contrib.auth import get_user_model

    for module in modules.all_modules():
        access = permission_objects([module.access_perm]).first()
        codes = permission_objects(module.permission_codes)
        for group in Group.objects.filter(permissions__in=codes).distinct():
            group.permissions.add(access)
        for user in get_user_model().objects.filter(user_permissions__in=codes).distinct():
            user.user_permissions.add(access)


def _sync_permission_names():
    """Mantém os nomes das permissões atualizados com os do código (create_permissions não os atualiza)."""
    from .models import PortalPermissions

    for codename, name in PortalPermissions._meta.permissions:
        Permission.objects.filter(content_type__app_label="portal", codename=codename).exclude(name=name).update(name=name)


def perm_required(code):
    """login + permissão, com página 403 em vez de redirecionar para o login."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(request, *args, **kwargs):
            module = modules.module_for_permission(code)
            if module and not modules.user_can_access(request.user, module):
                raise PermissionDenied  # sem acesso ao módulo, ou módulo desligado (também para superadministradores)
            if not request.user.has_perm(code):
                raise PermissionDenied
            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def has_admin() -> bool:
    """Existe pelo menos um utilizador ativo que consiga gerir utilizadores?"""
    User = get_user_model()
    return any(u.has_perm("portal.manage_users") for u in User.objects.filter(is_active=True))
