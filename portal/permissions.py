from functools import wraps

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import PermissionDenied

# (código completo, rótulo, descrição) agrupados para a matriz de permissões
PERMISSION_GROUPS = [
    ("Assinatura", [
        ("signing.can_sign", "Assinar ficheiros", "Usar a página de assinatura e a API, e gerir os seus próprios tokens."),
    ]),
    ("Consulta", [
        ("portal.view_all_history", "Ver o histórico de todos", "Sem isto só vê as suas próprias assinaturas."),
        ("portal.view_audit", "Ver a auditoria", "Registo de ações administrativas."),
    ]),
    ("Inventário", [
        ("inventory.view_inventorycertificate", "Ver o inventário", "Lista e detalhe dos certificados carregados no inventário."),
        ("inventory.manage_inventory", "Gerir o inventário", "Carregar, editar e apagar certificados do inventário."),
    ]),
    ("Administração", [
        ("portal.manage_certificates", "Gerir certificados", "Registar, editar, testar e desativar certificados."),
        ("portal.manage_users", "Gerir utilizadores", "Criar, editar, desativar e repor palavras-passe."),
        ("portal.manage_groups", "Gerir grupos", "Criar grupos e escolher as suas permissões."),
        ("portal.manage_tokens", "Gerir tokens de todos", "Ver e revogar tokens de qualquer utilizador."),
        ("portal.manage_settings", "Gerir definições", "SignTool, timestamp, limites e extensões."),
    ]),
]
ALL_PERMISSIONS = [code for _, items in PERMISSION_GROUPS for code, _, _ in items]

DEFAULT_GROUPS = {
    "Assinantes": ["signing.can_sign"],
    "Auditores": ["portal.view_all_history", "portal.view_audit", "inventory.view_inventorycertificate"],
    "Administradores": ALL_PERMISSIONS,
}


DEFAULT_GROUPS_VERSION = 2
NEW_IN_VERSION_2 = {"inventory.view_inventorycertificate", "inventory.manage_inventory"}


def permission_objects(codes):
    ids = []
    for code in codes:
        app, codename = code.split(".")
        ids.append(Permission.objects.get(content_type__app_label=app, codename=codename).pk)
    return Permission.objects.filter(pk__in=ids)


def ensure_default_groups(sender=None, **kwargs):
    """post_migrate: cria as permissões e os grupos base (sem alterar grupos já existentes)."""
    from django.apps import apps

    for label in ("signing", "portal", "inventory"):
        create_permissions(apps.get_app_config(label), verbosity=0)
    from signing.models import SiteSettings

    site = SiteSettings.load()
    upgrade = site.default_groups_version < DEFAULT_GROUPS_VERSION
    for name, codes in DEFAULT_GROUPS.items():
        group, created = Group.objects.get_or_create(name=name)
        if created:
            group.permissions.set(permission_objects(codes))
        elif upgrade:  # versão nova de permissões: só acrescenta as novas aos grupos base, nunca retira
            group.permissions.add(*permission_objects([c for c in codes if c in NEW_IN_VERSION_2]))
    if upgrade:
        site.default_groups_version = DEFAULT_GROUPS_VERSION
        site.save(update_fields=["default_groups_version"])


def perm_required(code):
    """login + permissão, com página 403 em vez de redirecionar para o login."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(request, *args, **kwargs):
            if not request.user.has_perm(code):
                raise PermissionDenied
            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def has_admin() -> bool:
    """Existe pelo menos um utilizador ativo que consiga gerir utilizadores?"""
    User = get_user_model()
    return any(u.has_perm("portal.manage_users") for u in User.objects.filter(is_active=True))
