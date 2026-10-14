from django import forms

from portal.forms import TailwindMixin

from .models import InventoryCertificate


class UploadForm(TailwindMixin, forms.Form):
    pfx_password = forms.CharField(label="Palavra-passe dos .pfx", required=False,
                                   widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "off"}),
                                   help_text="Usada para todos os .pfx deste envio. Não é guardada.")
    include_ca = forms.BooleanField(label="Incluir certificados de CA / cadeia", required=False,
                                    help_text="Por omissão só entram os certificados finais (servidor, cliente, etc.).")
    server = forms.CharField(label="Servidor / local", max_length=255, required=False,
                             help_text="Aplica-se a todos os certificados deste envio (ex.: VM-APP01).")
    owner = forms.CharField(label="Responsável", max_length=255, required=False)
    purpose = forms.CharField(label="Utilização", max_length=255, required=False)
    notes = forms.CharField(label="Notas", required=False, widget=forms.Textarea(attrs={"rows": 3}))


class MetaForm(TailwindMixin, forms.ModelForm):
    class Meta:
        model = InventoryCertificate
        fields = ["name", "server", "owner", "purpose", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 4})}
