from django import forms

from portal.forms import TailwindMixin

from .models import CertificateUsage, InventoryCertificate


class UsageFieldsMixin:
    """Valida que a utilização indica pelo menos o servidor, o IP ou a aplicação."""

    def clean(self):
        data = super().clean()
        if not any(data.get(f) for f in ("hostname", "ip_address", "application")):
            raise forms.ValidationError("Indique pelo menos o servidor, o IP ou a aplicação.")
        return data


class UploadForm(TailwindMixin, forms.Form):
    pfx_password = forms.CharField(label="Palavra-passe dos .pfx", required=False,
                                   widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "off"}),
                                   help_text="Usada para todos os .pfx deste envio. Não é guardada.")
    include_ca = forms.BooleanField(label="Incluir certificados de CA / cadeia", required=False,
                                    help_text="Por omissão só entram os certificados finais (servidor, cliente, etc.).")
    owner = forms.CharField(label="Responsável", max_length=255, required=False)
    notes = forms.CharField(label="Notas", required=False, widget=forms.Textarea(attrs={"rows": 3}))


class MetaForm(TailwindMixin, forms.ModelForm):
    class Meta:
        model = InventoryCertificate
        fields = ["name", "owner", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 4})}


class UsageForm(UsageFieldsMixin, TailwindMixin, forms.ModelForm):
    class Meta:
        model = CertificateUsage
        fields = ["hostname", "ip_address", "port", "application", "environment", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["environment"].choices = [("", "—")] + CertificateUsage.Environment.choices
