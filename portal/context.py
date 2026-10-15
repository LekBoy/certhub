from django.urls import reverse

from . import modules
from .icons import ICONS

PLATFORM_ADMIN_NAV = [
    ("Utilizadores", "portal:users", "users", "portal.manage_users"),
    ("Grupos", "portal:groups", "shield", "portal.manage_groups"),
    ("Módulos", "portal:modules", "puzzle", "portal.manage_modules"),
    ("Notificações", "portal:notifications", "mail", "portal.manage_notifications"),
    ("Auditoria", "portal:audit", "list", "portal.view_audit"),
]


def navigation(request):
    """Menu lateral: Painel, uma secção por módulo a que o utilizador tem acesso, e a Administração."""
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {}
    path = request.path

    sections, entries = [], []  # entries: (prefixo, item) para escolher o item ativo mais específico
    for module in modules.accessible_modules(user):
        items = []
        for it in module.nav:
            if it.perm and not user.has_perm(it.perm):
                continue
            item = {"label": it.label, "url": reverse(it.url_name), "icon": ICONS[it.icon], "active": False}
            items.append(item)
            entries.append(item)
        sections.append({"module": module, "items": items})

    admin_items = []
    for label, url_name, icon, perm in PLATFORM_ADMIN_NAV:
        if user.has_perm(perm):
            item = {"label": label, "url": reverse(url_name), "icon": ICONS[icon], "active": False}
            admin_items.append(item)
            entries.append(item)
    if user.is_superuser:
        item = {"label": "Admin técnico", "url": reverse("admin:index"), "icon": ICONS["cog"], "active": False}
        admin_items.append(item)
        entries.append(item)

    matches = [e for e in entries if path.startswith(e["url"])]
    if matches:
        max(matches, key=lambda e: len(e["url"]))["active"] = True
    return {
        "nav_sections": sections, "nav_admin": admin_items,
        "nav_home": {"url": reverse("portal:dashboard"), "icon": ICONS["home"], "active": path == reverse("portal:dashboard")},
    }
