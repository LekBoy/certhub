from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import Group, User

from signing.certinfo import CertificateError, parse_public_certificate
from signing.models import SigningCertificate, SiteSettings

from .permissions import PERMISSION_GROUPS, permission_objects

INPUT = "block w-full rounded-lg border-slate-300 text-sm shadow-sm focus:border-brand-500 focus:ring-brand-500"
CHECK = "h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"


class TailwindMixin:
    """Aplica as classes Tailwind aos widgets (o CSS é compilado a partir destes ficheiros)."""

    def style_widgets(self):
        for field in self.fields.values():
            w = field.widget
            if isinstance(w, (forms.CheckboxSelectMultiple,)):
                w.attrs["class"] = CHECK
            elif isinstance(w, forms.CheckboxInput):
                w.attrs["class"] = CHECK
            elif isinstance(w, forms.FileInput):
                w.attrs["class"] = ("block w-full text-sm text-slate-600 file:mr-4 file:rounded-lg file:border-0 "
                                    "file:bg-brand-50 file:px-4 file:py-2 file:text-sm file:font-semibold "
                                    "file:text-brand-700 hover:file:bg-brand-100")
            else:
                w.attrs["class"] = INPUT
            if isinstance(w, forms.Textarea):
                w.attrs.setdefault("rows", 3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.style_widgets()


def actor_perms(actor) -> set[str]:
    return actor.get_all_permissions()


class PasswordForm(TailwindMixin, PasswordChangeForm):
    pass


# ---------------------------------------------------------------- utilizadores
class UserForm(TailwindMixin, forms.ModelForm):
    groups = forms.ModelMultipleChoiceField(queryset=Group.objects.all(), required=False,
                                            widget=forms.CheckboxSelectMultiple, label="Grupos")

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active", "is_superuser", "groups"]
        labels = {"username": "Utilizador", "first_name": "Nome", "last_name": "Apelido", "email": "E-mail",
                  "is_active": "Conta ativa", "is_superuser": "Superadministrador (todas as permissões)"}

    def __init__(self, *args, actor, **kwargs):
        super().__init__(*args, **kwargs)
        self.actor = actor
        self.fields["is_active"].initial = True
        if not actor.is_superuser:
            del self.fields["is_superuser"]
        if self.instance.pk:
            self.fields["groups"].initial = self.instance.groups.all()

    def clean_groups(self):
        groups = self.cleaned_data["groups"]
        if self.actor.is_superuser:
            return groups
        current = set(self.instance.groups.values_list("pk", flat=True)) if self.instance.pk else set()
        mine = actor_perms(self.actor)
        for g in groups:
            if g.pk in current:
                continue
            missing = {f"{p.content_type.app_label}.{p.codename}" for p in g.permissions.select_related("content_type")} - mine
            if missing:
                raise forms.ValidationError(f"Não pode atribuir o grupo «{g.name}»: tem permissões que você não tem.")
        return groups

    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit:
            user.groups.set(self.cleaned_data["groups"])
        return user


# ---------------------------------------------------------------------- grupos
class GroupForm(TailwindMixin, forms.ModelForm):
    perms = forms.MultipleChoiceField(choices=[], required=False, widget=forms.CheckboxSelectMultiple, label="Permissões")
    members = forms.ModelMultipleChoiceField(queryset=User.objects.order_by("username"), required=False,
                                             widget=forms.CheckboxSelectMultiple, label="Membros")

    class Meta:
        model = Group
        fields = ["name"]
        labels = {"name": "Nome do grupo"}

    def __init__(self, *args, actor, **kwargs):
        super().__init__(*args, **kwargs)
        self.actor = actor
        self.fields["perms"].choices = [(c, l) for _, items in PERMISSION_GROUPS for c, l, _ in items]
        if self.instance.pk:
            self.fields["perms"].initial = [f"{p.content_type.app_label}.{p.codename}"
                                            for p in self.instance.permissions.select_related("content_type")]
            self.fields["members"].initial = self.instance.user_set.all()

    def clean_perms(self):
        perms = set(self.cleaned_data["perms"])
        if not self.actor.is_superuser:
            have = set(self.initial.get("perms", self.fields["perms"].initial or []))
            extra = perms - have - actor_perms(self.actor)
            if extra:
                raise forms.ValidationError("Não pode dar permissões que você próprio não tem.")
        return perms

    def save(self, commit=True):
        group = super().save(commit=commit)
        if commit:
            group.permissions.set(permission_objects(self.cleaned_data["perms"]))
            group.user_set.set(self.cleaned_data["members"])
        return group


# ---------------------------------------------------------------- certificados
class CertificateForm(TailwindMixin, forms.ModelForm):
    certificate_file = forms.FileField(
        label="Certificado público (.cer/.crt/.pem)", required=False,
        help_text="Só a parte pública. É rejeitado se não tiver a utilização Code Signing (1.3.6.1.5.5.7.3.3).")
    allowed_groups = forms.ModelMultipleChoiceField(queryset=Group.objects.all(), required=False,
                                                    widget=forms.CheckboxSelectMultiple, label="Grupos com acesso")

    class Meta:
        model = SigningCertificate
        fields = ["name", "is_active", "method", "store_name", "machine_store", "keypair_alias", "csp_name",
                  "cert_file_path", "custom_command", "timestamp_url", "verify", "allowed_groups",
                  "annual_limit", "subscription_start", "renewal_date", "notes"]
        widgets = {
            "subscription_start": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "renewal_date": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "custom_command": forms.Textarea(attrs={"rows": 7, "class": "font-mono"}),
        }
        help_texts = {"allowed_groups": "Vazio = qualquer utilizador com permissão de assinar."}

    parsed = None

    def clean_custom_command(self):
        text = self.cleaned_data["custom_command"]
        if text.strip():
            sample = dict.fromkeys(["signtool", "file", "thumbprint", "alias", "csp", "cert_file", "store",
                                    "timestamp_url"], "x")
            for line in text.splitlines():
                try:
                    line.format_map(sample)
                except (KeyError, IndexError, ValueError):
                    raise forms.ValidationError(f"Marcador desconhecido na linha: {line.strip()}")
        return text

    def clean(self):
        data = super().clean()
        upload = data.get("certificate_file")
        if not self.instance.pk and not upload:
            self.add_error("certificate_file", "Envie o certificado público.")
        if upload:
            try:
                self.parsed = parse_public_certificate(upload.read())
            except CertificateError as exc:
                self.add_error("certificate_file", str(exc))
            else:
                taken = SigningCertificate.objects.filter(thumbprint=self.parsed["thumbprint"]).exclude(pk=self.instance.pk)
                if taken.exists():
                    self.add_error("certificate_file", "Este certificado já está registado.")
        method = data.get("method")
        M = SigningCertificate.Method
        if method == M.KEYLOCKER_ALIAS:
            for f in ("csp_name", "keypair_alias", "cert_file_path"):
                if not data.get(f):
                    self.add_error(f, "Obrigatório neste método.")
        if method == M.CUSTOM and "{file}" not in (data.get("custom_command") or ""):
            self.add_error("custom_command", "O comando tem de conter {file}.")
        return data

    def save(self, commit=True):
        cert = super().save(commit=False)
        if self.parsed:
            for field, value in self.parsed.items():
                setattr(cert, field, value)
        if commit:
            cert.save()
            self.save_m2m()
        return cert


# ------------------------------------------------------------------ definições
class SiteSettingsForm(TailwindMixin, forms.ModelForm):
    class Meta:
        model = SiteSettings
        fields = ["signtool_path", "timestamp_url", "verify_after_sign", "timeout_seconds", "max_upload_mb",
                  "allowed_extensions", "token_valid_days", "block_at_limit"]

    def clean_allowed_extensions(self):
        value = self.cleaned_data["allowed_extensions"]
        if not [p for p in value.split(",") if p.strip()]:
            raise forms.ValidationError("Indique pelo menos uma extensão.")
        return value

    def clean(self):
        data = super().clean()
        for f in ("timeout_seconds", "max_upload_mb", "token_valid_days"):
            if data.get(f) is not None and data[f] < 1:
                self.add_error(f, "Tem de ser pelo menos 1.")
        return data
