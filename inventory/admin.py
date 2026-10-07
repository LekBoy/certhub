from django.contrib import admin, messages

from .models import Host

@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("name", "os", "environment", "owner", "is_active", "last_seen", "token_prefix", "token_expires_at")
    list_filter = ("os", "environment", "is_active")
    search_fields = ("name", "owner")
    readonly_fields = ("last_seen", "created_at", "token_prefix", "token_expires_at")
    actions = ["rotate_tokens"]

    def save_model(self, request, obj, form, change):
        raw = None if change else obj.set_new_token()
        super().save_model(request, obj, form, change)
        if raw:
            messages.warning(request, f"Token de {obj.name} (só aparece agora, copie-o): {raw}")

    @admin.action(description="Gerar novo token (invalida o anterior)")
    def rotate_tokens(self, request, queryset):
        for host in queryset:
            raw = host.set_new_token()
            host.save(update_fields=["token_hash", "token_prefix", "token_expires_at"])
            messages.warning(request, f"Novo token de {host.name} (só aparece agora): {raw}")