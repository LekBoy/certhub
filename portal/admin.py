from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group, User


class CertHubUserAdmin(UserAdmin):
    """Gestão de utilizadores: quem pode assinar / auditar faz-se por grupos."""

    list_display = ("username", "email", "first_name", "last_name", "grupos", "is_active", "is_staff", "last_login")
    list_filter = ("is_active", "is_staff", "is_superuser", "groups")
    actions = ["add_signers", "remove_signers", "deactivate"]

    @admin.display(description="Grupos")
    def grupos(self, obj):
        return ", ".join(g.name for g in obj.groups.all()) or "—"

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("groups")

    @admin.action(description="Dar permissão de assinatura (grupo Assinantes)")
    def add_signers(self, request, queryset):
        group = Group.objects.get(name="Assinantes")
        for user in queryset:
            user.groups.add(group)
        self.message_user(request, f"{queryset.count()} utilizador(es) adicionados a Assinantes.", messages.SUCCESS)

    @admin.action(description="Retirar permissão de assinatura")
    def remove_signers(self, request, queryset):
        group = Group.objects.get(name="Assinantes")
        for user in queryset:
            user.groups.remove(group)
        self.message_user(request, f"{queryset.count()} utilizador(es) removidos de Assinantes.", messages.SUCCESS)

    @admin.action(description="Desativar utilizadores")
    def deactivate(self, request, queryset):
        n = queryset.exclude(pk=request.user.pk).update(is_active=False)
        self.message_user(request, f"{n} utilizador(es) desativados.", messages.SUCCESS)


admin.site.unregister(User)
admin.site.register(User, CertHubUserAdmin)
