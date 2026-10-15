"""Administração dentro do CertHub: utilizadores, grupos, tokens, definições e auditoria."""
import os
import secrets

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth.views import PasswordChangeView
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.decorators.http import require_POST

from signing.models import SigningToken, SiteSettings

from .audit import audit
from .forms import GroupForm, NotificationSettingsForm, PasswordForm, SiteSettingsForm, UserForm
from .models import AuditEvent, NotificationLog, NotificationSettings, UserProfile
from . import modules, notify
from .permissions import PLATFORM_PERMISSION_GROUPS, has_admin, perm_required


class Lockout(Exception):
    pass


def _check_not_locked_out():
    if not has_admin():
        raise Lockout


LOCKOUT_MSG = "Operação cancelada: ficaria sem nenhum utilizador ativo capaz de gerir utilizadores."


def _temp_password(user) -> str:
    raw = secrets.token_urlsafe(9)
    user.set_password(raw)
    user.save(update_fields=["password"])
    profile = UserProfile.for_user(user)
    profile.must_change_password = True
    profile.save(update_fields=["must_change_password"])
    return raw


def _can_edit_user(actor, target) -> bool:
    return actor.is_superuser or not target.is_superuser


# ------------------------------------------------------------------ utilizadores
@perm_required("portal.manage_users")
def users(request):
    qs = User.objects.prefetch_related("groups").annotate(n_signed=Count("signing_requests"))
    q = request.GET.get("q", "").strip()
    status = request.GET.get("status", "")
    group = request.GET.get("group", "")
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(first_name__icontains=q) | Q(last_name__icontains=q)
                       | Q(email__icontains=q))
    if status == "active":
        qs = qs.filter(is_active=True)
    elif status == "inactive":
        qs = qs.filter(is_active=False)
    if group.isdigit():
        qs = qs.filter(groups__pk=int(group))
    page = Paginator(qs.order_by("username"), 25).get_page(request.GET.get("page"))
    keep = "&".join(f"{k}={v}" for k, v in (("q", q), ("status", status), ("group", group)) if v)
    return render(request, "portal/users.html", {
        "page": page, "q": q, "status": status, "group": group, "groups": Group.objects.all(), "keep": keep,
    })


@perm_required("portal.manage_users")
def user_create(request):
    form = UserForm(request.POST or None, actor=request.user)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            user = form.save()
            raw = _temp_password(user)
        audit(request, "user_created", user.username,
              f"grupos: {', '.join(g.name for g in user.groups.all()) or '—'}")
        return render(request, "portal/user_credentials.html", {"target": user, "temp_password": raw, "created": True})
    return render(request, "portal/user_form.html", {"form": form, "target": None})


@perm_required("portal.manage_users")
def user_edit(request, pk):
    target = get_object_or_404(User, pk=pk)
    if not _can_edit_user(request.user, target):
        messages.error(request, "Só um superadministrador pode alterar outro superadministrador.")
        return redirect("portal:users")
    form = UserForm(request.POST or None, instance=target, actor=request.user)
    if request.method == "POST" and form.is_valid():
        if target.pk == request.user.pk and not form.cleaned_data["is_active"]:
            form.add_error("is_active", "Não pode desativar a sua própria conta.")
        else:
            try:
                with transaction.atomic():
                    before = ", ".join(sorted(g.name for g in target.groups.all()))
                    form.save()
                    _check_not_locked_out()
                after = ", ".join(sorted(g.name for g in target.groups.all()))
                audit(request, "user_updated", target.username,
                      f"grupos: {before or '—'} → {after or '—'}; ativo: {target.is_active}")
                messages.success(request, f"Utilizador «{target.username}» atualizado.")
                return redirect("portal:users")
            except Lockout:
                form = UserForm(request.POST, instance=User.objects.get(pk=pk), actor=request.user)
                messages.error(request, LOCKOUT_MSG)
    return render(request, "portal/user_form.html", {
        "form": form, "target": target,
        "tokens": SigningToken.objects.filter(user=target).order_by("-created_at")[:5],
        "n_signed": target.signing_requests.count(),
    })


@perm_required("portal.manage_users")
@require_POST
def user_reset_password(request, pk):
    target = get_object_or_404(User, pk=pk)
    if not _can_edit_user(request.user, target):
        messages.error(request, "Só um superadministrador pode alterar outro superadministrador.")
        return redirect("portal:users")
    raw = _temp_password(target)
    audit(request, "password_reset", target.username)
    return render(request, "portal/user_credentials.html", {"target": target, "temp_password": raw, "created": False})


@perm_required("portal.manage_users")
@require_POST
def user_delete(request, pk):
    target = get_object_or_404(User, pk=pk)
    if target.pk == request.user.pk:
        messages.error(request, "Não pode apagar a sua própria conta.")
    elif not _can_edit_user(request.user, target):
        messages.error(request, "Só um superadministrador pode apagar outro superadministrador.")
    elif target.signing_requests.exists():
        messages.error(request, "Este utilizador tem histórico de assinaturas e não pode ser apagado. Desative a conta.")
    else:
        try:
            with transaction.atomic():
                name = target.username
                target.delete()
                _check_not_locked_out()
            audit(request, "user_deleted", name)
            messages.success(request, f"Utilizador «{name}» apagado.")
        except Lockout:
            messages.error(request, LOCKOUT_MSG)
    return redirect("portal:users")


# ------------------------------------------------------------------------ grupos
@perm_required("portal.manage_groups")
def groups(request):
    from .forms import permission_labels

    labels = dict(permission_labels())
    q = request.GET.get("q", "").strip()
    qs = Group.objects.annotate(n_members=Count("user", distinct=True)).prefetch_related("permissions__content_type", "user_set")
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(user__username__icontains=q)).distinct()
    rows = []
    for g in qs.order_by("name"):
        codes = [f"{p.content_type.app_label}.{p.codename}" for p in g.permissions.all()]
        accessible = [m for m in modules.all_modules() if m.access_perm in codes]
        inner = [labels[c] for c in codes if c in labels and not any(c == m.access_perm for m in modules.all_modules())]
        rows.append({
            "group": g, "modules": accessible, "permissions": sorted(inner),
            "members": sorted(u.username for u in g.user_set.all()),
        })
    return render(request, "portal/groups.html", {"rows": rows, "q": q, "total": Group.objects.count()})


def _permission_groups():
    """Grupos de opções para a lista de permissões: Plataforma e, por módulo, o acesso + as permissões."""
    out = [{"label": "Plataforma", "options": [
        {"value": c, "label": l, "desc": d, "module": "", "access": False}
        for _, rows in PLATFORM_PERMISSION_GROUPS for c, l, d in rows]}]
    for m in modules.all_modules():
        out.append({"label": f"{m.name} · Acesso", "options": [
            {"value": m.access_perm, "label": f"Acesso ao módulo {m.name}", "desc": m.description,
             "module": m.key, "access": True}]})
        for title, rows in m.permission_groups:
            out.append({"label": f"{m.name} · {title}", "options": [
                {"value": c, "label": l, "desc": d, "module": m.key, "access": False} for c, l, d in rows]})
    return out


def _split(groups, chosen):
    """Divide os grupos de opções em (disponíveis, escolhidas), mantendo a ordem original (data-order)."""
    available, picked, n = [], [], 0
    for gi, g in enumerate(groups):
        a_opts, c_opts = [], []
        for opt in g["options"]:
            opt = {**opt, "order": n}
            n += 1
            (c_opts if opt["value"] in chosen else a_opts).append(opt)
        if a_opts:
            available.append({"label": g["label"], "order": gi, "options": a_opts})
        if c_opts:
            picked.append({"label": g["label"], "order": gi, "options": c_opts})
    return available, picked


def _group_form_context(form, group):
    selected = {str(v) for v in (form["perms"].value() or [])}
    members = {str(v) for v in (form["members"].value() or [])}
    perm_available, perm_chosen = _split(_permission_groups(), selected)
    people = [{"label": "", "options": [
        {"value": str(u.pk), "label": u.username + (f" · {u.get_full_name()}" if u.get_full_name() else ""),
         "desc": u.email, "module": "", "access": False} for u in form.fields["members"].queryset]}]
    member_available, member_chosen = _split(people, members)
    return {
        "form": form, "group": group, "selected": selected,
        "perm_available": perm_available, "perm_chosen": perm_chosen,
        "member_available": member_available, "member_chosen": member_chosen,
        "n_perm_chosen": sum(len(g["options"]) for g in perm_chosen),
    }


@perm_required("portal.manage_groups")
def group_create(request):
    form = GroupForm(request.POST or None, actor=request.user)
    if request.method == "POST" and form.is_valid():
        group = form.save()
        audit(request, "group_created", group.name, f"permissões: {', '.join(sorted(form.cleaned_data['perms'])) or '—'}")
        messages.success(request, f"Grupo «{group.name}» criado.")
        return redirect("portal:groups")
    return render(request, "portal/group_form.html", _group_form_context(form, None))


@perm_required("portal.manage_groups")
def group_edit(request, pk):
    group = get_object_or_404(Group, pk=pk)
    form = GroupForm(request.POST or None, instance=group, actor=request.user)
    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                form.save()
                _check_not_locked_out()
            audit(request, "group_updated", group.name,
                  f"permissões: {', '.join(sorted(form.cleaned_data['perms'])) or '—'}; "
                  f"membros: {form.cleaned_data['members'].count()}")
            messages.success(request, f"Grupo «{group.name}» atualizado.")
            return redirect("portal:groups")
        except Lockout:
            messages.error(request, LOCKOUT_MSG)
            form = GroupForm(request.POST, instance=Group.objects.get(pk=pk), actor=request.user)
    return render(request, "portal/group_form.html", _group_form_context(form, group))


@perm_required("portal.manage_groups")
@require_POST
def group_delete(request, pk):
    group = get_object_or_404(Group, pk=pk)
    try:
        with transaction.atomic():
            name = group.name
            group.delete()
            _check_not_locked_out()
        audit(request, "group_deleted", name)
        messages.success(request, f"Grupo «{name}» apagado.")
    except Lockout:
        messages.error(request, LOCKOUT_MSG)
    return redirect("portal:groups")


# ------------------------------------------------------------------------ tokens
@perm_required("portal.manage_tokens")
def tokens_all(request):
    qs = SigningToken.objects.select_related("user").order_by("-created_at")
    return render(request, "portal/tokens_all.html", {"tokens": qs})


@perm_required("portal.manage_tokens")
@require_POST
def token_revoke(request, pk):
    token = get_object_or_404(SigningToken, pk=pk)
    token.is_active = False
    token.save(update_fields=["is_active"])
    audit(request, "token_revoked", f"{token.name} ({token.user.username})")
    messages.success(request, f"Token «{token.name}» de {token.user.username} revogado.")
    return redirect("portal:tokens_all")


# -------------------------------------------------------------------- definições
ENV_VARS = ["SM_HOST", "SM_API_KEY", "SM_CLIENT_CERT_FILE", "SM_CLIENT_CERT_PASSWORD"]


@perm_required("portal.manage_settings")
def settings_page(request):
    site = SiteSettings.load()
    form = SiteSettingsForm(request.POST or None, instance=site)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit(request, "settings_updated", "definições", ", ".join(sorted(form.changed_data)))
        messages.success(request, "Definições guardadas.")
        return redirect("portal:settings")
    env = [(name, bool(os.environ.get(name))) for name in ENV_VARS]
    return render(request, "portal/settings.html", {"form": form, "env": env})


# ------------------------------------------------------------------ notificações
NOTIFY_ENV_VARS = [notify.SMTP_PASSWORD_ENV, notify.GRAPH_SECRET_ENV]


@perm_required("portal.manage_notifications")
def notifications(request):
    cfg = NotificationSettings.load()
    form = NotificationSettingsForm(request.POST or None, instance=cfg)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit(request, "notifications_updated", "notificações", ", ".join(sorted(form.changed_data)))
        messages.success(request, "Notificações guardadas.")
        return redirect("portal:notifications")
    env = [(name, bool(os.environ.get(name))) for name in NOTIFY_ENV_VARS]
    pending = notify.pending_alerts(cfg)
    return render(request, "portal/notifications.html", {
        "form": form, "cfg": cfg, "env": env, "pending": pending,
        "log": NotificationLog.objects.all()[:15]})


@require_POST
@perm_required("portal.manage_notifications")
def notifications_test(request):
    ok, err = notify.send_test(request.user.username)
    audit(request, "notifications_test", "notificações", "ok" if ok else err[:200])
    if ok:
        messages.success(request, "E-mail de teste enviado. Confirme na caixa do Outlook.")
    else:
        messages.error(request, f"Falhou o envio: {err}")
    return redirect("portal:notifications")


@require_POST
@perm_required("portal.manage_notifications")
def notifications_run(request):
    res = notify.run_alerts()
    audit(request, "notifications_run", "notificações", f"{res['alerts']} aviso(s)")
    if res["skipped"]:
        messages.warning(request, res["skipped"])
    elif res["error"]:
        messages.error(request, f"Falhou o envio: {res['error']}")
    elif res["alerts"]:
        messages.success(request, f"{res['alerts']} aviso(s) enviado(s).")
    else:
        messages.info(request, "Nada para avisar neste momento.")
    return redirect("portal:notifications")


# ---------------------------------------------------------------------- auditoria
@perm_required("portal.view_audit")
def audit_log(request):
    qs = AuditEvent.objects.all()
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(action__icontains=q) | Q(target__icontains=q)
                       | Q(detail__icontains=q))
    page = Paginator(qs, 30).get_page(request.GET.get("page"))
    return render(request, "portal/audit.html", {"page": page, "q": q, "keep": f"q={q}" if q else ""})


# ------------------------------------------------------------------------- conta
@login_required
def account(request):
    if request.method == "POST":
        u = request.user
        u.first_name = request.POST.get("first_name", "").strip()[:150]
        u.last_name = request.POST.get("last_name", "").strip()[:150]
        u.email = request.POST.get("email", "").strip()[:254]
        u.save(update_fields=["first_name", "last_name", "email"])
        messages.success(request, "Dados guardados.")
        return redirect("portal:account")
    return render(request, "portal/account.html")


class PasswordChange(PasswordChangeView):
    template_name = "portal/password.html"
    form_class = PasswordForm
    success_url = reverse_lazy("portal:dashboard")

    def form_valid(self, form):
        response = super().form_valid(form)
        profile = UserProfile.for_user(self.request.user)
        if profile.must_change_password:
            profile.must_change_password = False
            profile.save(update_fields=["must_change_password"])
        messages.success(self.request, "Palavra-passe alterada.")
        return response


# ---------------------------------------------------------------------- módulos
@perm_required("portal.manage_modules")
def modules_page(request):
    from django.contrib.auth import get_user_model

    active_users = list(get_user_model().objects.filter(is_active=True))
    rows = []
    for m in modules.all_modules():
        rows.append({
            "module": m, "enabled": modules.is_enabled(m),
            "n_users": sum(modules.user_can_access(u, m) for u in active_users),
            "groups": Group.objects.filter(permissions__codename=m.access_perm.split(".")[1]).order_by("name"),
        })
    return render(request, "portal/modules.html", {"rows": rows})


@perm_required("portal.manage_modules")
@require_POST
def module_toggle(request, key):
    from .models import ModuleState

    module = modules.get(key)
    if module is None:
        raise Http404
    state, _ = ModuleState.objects.get_or_create(key=key)
    state.enabled = not state.enabled
    state.save()
    audit(request, "module_enabled" if state.enabled else "module_disabled", module.name)
    messages.success(request, f"Módulo «{module.name}» {'ligado' if state.enabled else 'desligado'}.")
    return redirect("portal:modules")
