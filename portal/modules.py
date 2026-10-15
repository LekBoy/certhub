"""Registo de módulos do InfraHub.

Um módulo declara o seu nome, o menu, o prefixo de URL, o seu acesso e as suas permissões. A plataforma
trata do resto: menu, acesso por módulo, painel, página «Módulos» e a matriz de permissões dos grupos.

Regra central: as permissões de um módulo só valem se o utilizador tiver o ACESSO a esse módulo
(e o módulo estiver ligado). Está aplicada num único sítio: `portal.backends.ModuleAccessBackend`
(+ `portal.middleware.ModuleAccessMiddleware` para os endereços do módulo).
Para criar um módulo novo ver docs/modules.md.
"""
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class NavItem:
    label: str
    url_name: str
    icon: str
    perm: str | None = None  # permissão extra, além do acesso ao módulo


@dataclass
class Module:
    key: str
    name: str
    description: str
    icon: str
    url_prefix: str  # ex.: "/certhub/"
    home_url_name: str
    access_perm: str  # ex.: "portal.access_certhub"
    nav: list = field(default_factory=list)
    permission_groups: list = field(default_factory=list)  # [(título, [(código, rótulo, descrição)])]
    dashboard: Callable | None = None  # request -> dict (contexto do widget) ou None
    dashboard_template: str | None = None

    @property
    def permission_codes(self) -> list[str]:
        return [code for _, items in self.permission_groups for code, _, _ in items]

    @property
    def all_codes(self) -> list[str]:
        return [self.access_perm, *self.permission_codes]


_REGISTRY: dict[str, Module] = {}
_BY_PERMISSION: dict[str, Module] = {}


def register(module: Module) -> Module:
    _REGISTRY[module.key] = module
    for code in module.all_codes:
        _BY_PERMISSION[code] = module
    return module


def all_modules() -> list[Module]:
    return list(_REGISTRY.values())


def get(key: str) -> Module | None:
    return _REGISTRY.get(key)


def module_for_permission(code: str) -> Module | None:
    return _BY_PERMISSION.get(code)


def module_for_path(path: str) -> Module | None:
    return next((m for m in _REGISTRY.values() if path.startswith(m.url_prefix)), None)


def disabled_keys(user=None) -> set[str]:
    """Chaves dos módulos desligados. Fica em memória no objeto `user` (uma consulta por pedido)."""
    from .models import ModuleState

    if user is not None and hasattr(user, "_disabled_modules"):
        return user._disabled_modules
    keys = set(ModuleState.objects.filter(enabled=False).values_list("key", flat=True))
    if user is not None:
        user._disabled_modules = keys
    return keys


def is_enabled(module: Module, user=None) -> bool:
    return module.key not in disabled_keys(user)


def user_can_access(user, module: Module) -> bool:
    """Acesso ao módulo: sessão ativa, módulo ligado e permissão de acesso (ou superadministrador)."""
    if not (user and user.is_authenticated and user.is_active):
        return False
    return is_enabled(module, user) and user.has_perm(module.access_perm)


def accessible_modules(user) -> list[Module]:
    return [m for m in all_modules() if user_can_access(user, m)]
