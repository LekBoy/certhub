from django import forms
from django.contrib import admin, messages

from .certinfo import CertificateError, parse_public_certificate
from .models import SigningCertificate, SigningRequest, SigningToken


class SigningCertificateForm(forms.ModelForm):
    certificate_file = forms.FileField(
        label="Certificado público (.cer/.crt/.pem)", required=False,
        help_text="Só a parte pública. A private key (.pfx) deve ficar importada no store do servidor de assinatura, "
                  "como não-exportável.",
    )

    class Meta:
        model = SigningCertificate
        fields = ("name", "store_name", "machine_store", "is_active")

    def clean(self):
        data = super().clean()
        upload = data.get("certificate_file")
        if not self.instance.pk and not upload:
            raise forms.ValidationError("Envie o certificado público.")
        if upload:
            try:
                self.parsed = parse_public_certificate(upload.read())
            except CertificateError as exc:
                raise forms.ValidationError(str(exc))
        return data


@admin.register(SigningCertificate)
class SigningCertificateAdmin(admin.ModelAdmin):
    form = SigningCertificateForm
    list_display = ("name", "thumbprint", "subject", "not_after", "is_active")
    readonly_fields = ("thumbprint", "subject", "not_before", "not_after")

    def save_model(self, request, obj, form, change):
        for field, value in getattr(form, "parsed", {}).items():
            setattr(obj, field, value)
        super().save_model(request, obj, form, change)


@admin.register(SigningToken)
class SigningTokenAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "token_prefix", "expires_at", "is_active", "last_used")
    fields = ("user", "name", "is_active")

    def save_model(self, request, obj, form, change):
        raw = None if change else obj.set_new_token()
        super().save_model(request, obj, form, change)
        if raw:
            messages.warning(request, f"Token '{obj.name}' (só aparece agora, copie-o): {raw}")


@admin.register(SigningRequest)
class SigningRequestAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "filename", "certificate", "status", "via_api")
    list_filter = ("status", "via_api", "certificate")
    search_fields = ("filename", "sha256_original", "sha256_signed")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
