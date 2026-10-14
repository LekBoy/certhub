import datetime

from django.contrib.auth.models import Group, Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from signing.models import SigningCertificate, SigningRequest, SigningToken, SiteSettings
from signing.tests import make_cert, make_pfx

from .models import AuditEvent, UserProfile


class ManageBase(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("boss", password="x")
        self.admin.groups.add(Group.objects.get(name="Administradores"))
        self.client.force_login(self.admin)

    def user_in(self, name, *groups):
        u = User.objects.create_user(name, password="x")
        for g in groups:
            u.groups.add(Group.objects.get(name=g))
        return u


class GroupsAndPermissionsTests(ManageBase):
    def test_default_groups(self):
        names = set(Group.objects.values_list("name", flat=True))
        self.assertTrue({"Assinantes", "Auditores", "Administradores"} <= names)
        self.assertTrue(self.admin.has_perm("portal.manage_users"))
        self.assertFalse(self.user_in("s", "Assinantes").has_perm("portal.manage_users"))

    def test_pages_require_permission(self):
        self.client.force_login(self.user_in("s", "Assinantes"))
        for url in ("/manage/users/", "/manage/groups/", "/manage/settings/", "/manage/audit/",
                    "/manage/tokens/", "/certificates/new/"):
            self.assertEqual(self.client.get(url).status_code, 403, url)

    def test_create_group_with_permissions_and_members(self):
        member = self.user_in("m")
        r = self.client.post("/manage/groups/new/", {
            "name": "Equipa PAD", "perms": ["signing.can_sign", "portal.view_audit"], "members": [member.pk]})
        self.assertRedirects(r, "/manage/groups/")
        g = Group.objects.get(name="Equipa PAD")
        self.assertEqual({p.codename for p in g.permissions.all()}, {"can_sign", "view_audit"})
        self.assertTrue(member.has_perm("signing.can_sign"))
        self.assertTrue(AuditEvent.objects.filter(action="group_created", target="Equipa PAD").exists())

    def test_edit_group_permissions(self):
        g = Group.objects.get(name="Assinantes")
        self.client.post(f"/manage/groups/{g.pk}/", {"name": "Assinantes", "perms": ["portal.view_all_history"]})
        self.assertEqual([p.codename for p in g.permissions.all()], ["view_all_history"])

    def test_cannot_remove_last_admin_via_group(self):
        g = Group.objects.get(name="Administradores")
        r = self.client.post(f"/manage/groups/{g.pk}/", {"name": "Administradores", "perms": ["signing.can_sign"]})
        self.assertEqual(r.status_code, 200)  # ficou na página com erro
        self.assertTrue(g.permissions.filter(codename="manage_users").exists())

    def test_cannot_delete_group_that_leaves_no_admin(self):
        g = Group.objects.get(name="Administradores")
        self.client.post(f"/manage/groups/{g.pk}/delete/")
        self.assertTrue(Group.objects.filter(pk=g.pk).exists())

    def test_delete_other_group(self):
        g = Group.objects.get(name="Auditores")
        self.client.post(f"/manage/groups/{g.pk}/delete/")
        self.assertFalse(Group.objects.filter(pk=g.pk).exists())

    def test_cannot_grant_permissions_you_lack(self):
        mgr = self.user_in("mgr")
        mgr.user_permissions.add(*Permission.objects.filter(codename__in=["manage_groups"]))
        self.client.force_login(mgr)
        r = self.client.post("/manage/groups/new/", {"name": "Hack", "perms": ["portal.manage_settings"]})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Group.objects.filter(name="Hack").exists())


class UserManagementTests(ManageBase):
    def test_create_user_generates_temp_password(self):
        g = Group.objects.get(name="Assinantes")
        r = self.client.post("/manage/users/new/", {
            "username": "ana", "first_name": "Ana", "email": "a@x.pt", "is_active": "on", "groups": [g.pk]})
        self.assertEqual(r.status_code, 200)
        raw = r.context["temp_password"]
        u = User.objects.get(username="ana")
        self.assertTrue(u.check_password(raw))
        self.assertTrue(UserProfile.for_user(u).must_change_password)
        self.assertTrue(u.groups.filter(name="Assinantes").exists())

    def test_forced_password_change(self):
        u = self.user_in("t", "Assinantes")
        profile = UserProfile.for_user(u)
        profile.must_change_password = True
        profile.save()
        self.client.force_login(u)
        self.assertRedirects(self.client.get("/"), "/account/password/")
        r = self.client.post("/account/password/", {
            "old_password": "x", "new_password1": "Zq!9-long-pass-77", "new_password2": "Zq!9-long-pass-77"})
        self.assertRedirects(r, "/")
        profile.refresh_from_db()
        self.assertFalse(profile.must_change_password)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_weak_password_rejected(self):
        u = self.user_in("t")
        self.client.force_login(u)
        r = self.client.post("/account/password/", {"old_password": "x", "new_password1": "123", "new_password2": "123"})
        self.assertEqual(r.status_code, 200)

    def test_edit_user_groups_and_deactivate(self):
        u = self.user_in("b")
        g = Group.objects.get(name="Auditores")
        self.client.post(f"/manage/users/{u.pk}/", {"username": "b", "is_active": "", "groups": [g.pk]})
        u.refresh_from_db()
        self.assertFalse(u.is_active)
        self.assertTrue(u.groups.filter(pk=g.pk).exists())

    def test_cannot_deactivate_self(self):
        self.client.post(f"/manage/users/{self.admin.pk}/", {"username": "boss", "groups": []})
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)
        self.assertTrue(self.admin.groups.exists())

    def test_cannot_remove_last_admin(self):
        other = self.user_in("o")
        self.client.force_login(other)  # sem permissões: não passa
        self.assertEqual(self.client.post(f"/manage/users/{self.admin.pk}/", {"username": "boss"}).status_code, 403)

    def test_last_admin_lockout_guard(self):
        helper = self.user_in("h", "Administradores")
        # remover o grupo ao próprio helper deixaria boss (admin) — ok; remover a boss e helper não
        self.client.post(f"/manage/users/{helper.pk}/", {"username": "h", "is_active": "on", "groups": []})
        self.assertFalse(helper.groups.exists())
        # agora só boss é admin: boss não se pode apagar nem desativar (já coberto) -> outro admin não existe
        self.client.post(f"/manage/users/{self.admin.pk}/delete/")
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())

    def test_delete_user_without_history(self):
        u = self.user_in("gone")
        self.client.post(f"/manage/users/{u.pk}/delete/")
        self.assertFalse(User.objects.filter(pk=u.pk).exists())

    def test_cannot_delete_user_with_history(self):
        u = self.user_in("hist")
        cert = SigningCertificate.objects.create(name="c", thumbprint="1" * 40, subject="x",
                                                 not_before=datetime.datetime.now(datetime.timezone.utc),
                                                 not_after=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=9))
        SigningRequest.objects.create(user=u, certificate=cert, filename="a.dll", size=1, sha256_original="a" * 64, status="ok")
        self.client.post(f"/manage/users/{u.pk}/delete/")
        self.assertTrue(User.objects.filter(pk=u.pk).exists())

    def test_reset_password(self):
        u = self.user_in("r")
        r = self.client.post(f"/manage/users/{u.pk}/reset-password/")
        u.refresh_from_db()
        self.assertTrue(u.check_password(r.context["temp_password"]))
        self.assertTrue(UserProfile.for_user(u).must_change_password)

    def test_only_superuser_edits_superuser(self):
        root = User.objects.create_superuser("root", password="x")
        self.assertRedirects(self.client.get(f"/manage/users/{root.pk}/"), "/manage/users/")
        self.assertRedirects(self.client.post(f"/manage/users/{root.pk}/delete/"), "/manage/users/")
        self.assertTrue(User.objects.filter(pk=root.pk).exists())

    def test_non_superuser_cannot_set_superuser_flag(self):
        r = self.client.get("/manage/users/new/")
        self.assertNotIn("is_superuser", r.context["form"].fields)

    def test_list_filter_and_search(self):
        self.user_in("zeca", "Assinantes")
        r = self.client.get("/manage/users/?q=zec")
        self.assertEqual([u.username for u in r.context["page"]], ["zeca"])


class TokenAdminTests(ManageBase):
    def test_admin_can_revoke_any_token(self):
        u = self.user_in("dev", "Assinantes")
        t = SigningToken(user=u, name="ci")
        t.set_new_token()
        t.save()
        self.client.post(f"/manage/tokens/{t.pk}/revoke/")
        t.refresh_from_db()
        self.assertFalse(t.valid)

    def test_token_validity_from_settings(self):
        s = SiteSettings.load()
        s.token_valid_days = 7
        s.save()
        u = self.user_in("dev", "Assinantes")
        self.client.force_login(u)
        self.client.post("/tokens/", {"name": "x"})
        days = (SigningToken.objects.get().expires_at - SigningToken.objects.get().created_at).days
        self.assertIn(days, (6, 7))


class SettingsAndAuditTests(ManageBase):
    def test_update_settings(self):
        s = SiteSettings.load()
        r = self.client.post("/manage/settings/", {
            "signtool_path": r"D:\signtool.exe", "timestamp_url": "http://tsa/ts", "verify_after_sign": "on",
            "timeout_seconds": 60, "max_upload_mb": 10, "allowed_extensions": ".dll, exe", "token_valid_days": 30})
        self.assertRedirects(r, "/manage/settings/")
        s.refresh_from_db()
        self.assertEqual(s.signtool_path, r"D:\signtool.exe")
        self.assertEqual(s.extensions, {".dll", ".exe"})
        self.assertFalse(s.block_at_limit)
        self.assertTrue(AuditEvent.objects.filter(action="settings_updated").exists())

    def test_settings_validation(self):
        r = self.client.post("/manage/settings/", {
            "signtool_path": "x", "timeout_seconds": 0, "max_upload_mb": 1, "allowed_extensions": " , ", "token_valid_days": 1})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors)

    def test_secrets_never_shown(self):
        import os
        os.environ["SM_API_KEY"] = "super-secret-value"
        try:
            self.assertNotContains(self.client.get("/manage/settings/"), "super-secret-value")
        finally:
            del os.environ["SM_API_KEY"]

    def test_audit_page_and_filter(self):
        self.client.post("/manage/groups/new/", {"name": "G1"})
        r = self.client.get("/manage/audit/?q=G1")
        self.assertEqual(len(r.context["page"]), 1)
        self.assertEqual(r.context["page"][0].username, "boss")


class CertificateManagementTests(ManageBase):
    def payload(self, **extra):
        data = {"name": "PAD", "is_active": "on", "method": "store", "store_name": "My", "machine_store": "on",
                "verify": "default", "certificate_file": SimpleUploadedFile("a.cer", make_cert())}
        data.update(extra)
        return data

    def test_register_certificate(self):
        r = self.client.post("/certificates/new/", self.payload(annual_limit=1000, notes="renova em 2027"))
        cert = SigningCertificate.objects.get()
        self.assertRedirects(r, f"/certificates/{cert.pk}/")
        self.assertEqual(len(cert.thumbprint), 40)
        self.assertEqual(cert.annual_limit, 1000)

    def test_rejects_certificate_without_code_signing(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        bad = SimpleUploadedFile("a.cer", make_cert(ExtendedKeyUsageOID.SERVER_AUTH))
        r = self.client.post("/certificates/new/", self.payload(certificate_file=bad))
        self.assertEqual(r.status_code, 200)
        self.assertFalse(SigningCertificate.objects.exists())

    def test_keylocker_alias_requires_fields(self):
        r = self.client.post("/certificates/new/", self.payload(method="keylocker_alias"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("csp_name", r.context["form"].errors)

    def test_custom_command_needs_file_marker(self):
        r = self.client.post("/certificates/new/", self.payload(method="custom", custom_command="tool\nsign"))
        self.assertIn("custom_command", r.context["form"].errors)

    def test_duplicate_certificate_rejected(self):
        pem = make_cert()
        self.client.post("/certificates/new/", self.payload(certificate_file=SimpleUploadedFile("a.cer", pem)))
        r = self.client.post("/certificates/new/", self.payload(name="Outro", certificate_file=SimpleUploadedFile("b.cer", pem)))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SigningCertificate.objects.count(), 1)

    def test_edit_and_preview(self):
        self.client.post("/certificates/new/", self.payload())
        cert = SigningCertificate.objects.get()
        r = self.client.post(f"/certificates/{cert.pk}/", {
            "name": "PAD2", "is_active": "on", "method": "keylocker_thumbprint", "verify": "no",
            "allowed_groups": [Group.objects.get(name="Assinantes").pk]})
        self.assertRedirects(r, f"/certificates/{cert.pk}/")
        cert.refresh_from_db()
        self.assertEqual(cert.name, "PAD2")
        self.assertEqual(cert.allowed_groups.count(), 1)
        self.assertIn("/sha1", self.client.get(f"/certificates/{cert.pk}/").context["preview"])

    def test_test_signing_button(self):
        from unittest import mock
        self.client.post("/certificates/new/", self.payload())
        cert = SigningCertificate.objects.get()
        s = SiteSettings.load()
        s.verify_after_sign = False
        s.save()
        ok = mock.Mock(returncode=0, stdout="Successfully signed", stderr="")
        with mock.patch("signing.signer.subprocess.run", return_value=ok):
            r = self.client.post(f"/certificates/{cert.pk}/test/")
        self.assertTrue(r.context["test_ok"])
        self.assertIn("Successfully signed", r.context["test_output"])
        self.assertFalse(SigningRequest.objects.exists())  # o teste não conta nem entra no histórico

    def test_test_signing_failure_shown(self):
        from unittest import mock
        self.client.post("/certificates/new/", self.payload())
        cert = SigningCertificate.objects.get()
        bad = mock.Mock(returncode=1, stdout="", stderr="No certificates were found")
        with mock.patch("signing.signer.subprocess.run", return_value=bad):
            r = self.client.post(f"/certificates/{cert.pk}/test/")
        self.assertFalse(r.context["test_ok"])
        self.assertIn("No certificates", r.context["test_output"])

    def test_delete_certificate(self):
        self.client.post("/certificates/new/", self.payload())
        cert = SigningCertificate.objects.get()
        self.client.post(f"/certificates/{cert.pk}/delete/")
        self.assertFalse(SigningCertificate.objects.exists())

    def test_cannot_delete_used_certificate(self):
        self.client.post("/certificates/new/", self.payload())
        cert = SigningCertificate.objects.get()
        SigningRequest.objects.create(user=self.admin, certificate=cert, filename="a.dll", size=1,
                                      sha256_original="a" * 64, status="ok")
        self.client.post(f"/certificates/{cert.pk}/delete/")
        self.assertTrue(SigningCertificate.objects.exists())

    def test_dashboard_shows_limit_and_renewal_alerts(self):
        self.client.post("/certificates/new/", self.payload(annual_limit=1))
        cert = SigningCertificate.objects.get()
        cert.renewal_date = datetime.date.today() + datetime.timedelta(days=5)
        cert.save()
        SigningRequest.objects.create(user=self.admin, certificate=cert, filename="a.dll", size=1,
                                      sha256_original="a" * 64, status="ok")
        r = self.client.get("/")
        self.assertContains(r, "Limite anual atingido")
        self.assertContains(r, "Renovação em")


class PfxUploadTests(ManageBase):
    def post_pfx(self, pfx, password="s3cret", **extra):
        data = {"name": "Do PFX", "is_active": "on", "method": "store", "store_name": "My", "machine_store": "on",
                "verify": "default", "pfx_file": SimpleUploadedFile("c.pfx", pfx), "pfx_password": password}
        data.update(extra)
        return self.client.post("/certificates/new/", data, follow=True)

    def test_register_from_pfx_stores_only_public_data(self):
        r = self.post_pfx(make_pfx())
        cert = SigningCertificate.objects.get()
        self.assertEqual((cert.source, cert.had_private_key, cert.key_info), ("pfx", True, "RSA 2048 bits"))
        self.assertIn("Empresa PAD", cert.subject)
        self.assertEqual(len(cert.thumbprint), 40)
        text = " ".join(str(m) for m in r.context["messages"])
        self.assertIn("não foram guardados", text)
        self.assertIn("chave privada", text)

    def test_pfx_and_password_never_persisted(self):
        import os
        from django.conf import settings
        self.post_pfx(make_pfx(), password="never-store-me")
        for c in SigningCertificate.objects.all():
            for value in vars(c).values():
                self.assertNotIn("never-store-me", str(value))
        self.assertNotIn("never-store-me", " ".join(AuditEventText()))
        self.assertFalse(any(f.endswith((".pfx", ".p12")) for _, _, fs in os.walk(settings.BASE_DIR / "static") for f in fs))

    def test_wrong_pfx_password_shows_error(self):
        r = self.client.post("/certificates/new/", {
            "name": "x", "is_active": "on", "method": "store", "verify": "default",
            "pfx_file": SimpleUploadedFile("c.pfx", make_pfx()), "pfx_password": "bad"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("pfx_password", r.context["form"].errors)
        self.assertNotContains(r, 'value="bad"')
        self.assertFalse(SigningCertificate.objects.exists())

    def test_pfx_without_code_signing_rejected(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        r = self.post_pfx(make_pfx(eku=ExtendedKeyUsageOID.SERVER_AUTH))
        self.assertFalse(SigningCertificate.objects.exists())

    def test_cannot_send_both_files(self):
        r = self.client.post("/certificates/new/", {
            "name": "x", "is_active": "on", "method": "store", "verify": "default",
            "certificate_file": SimpleUploadedFile("a.cer", make_cert()),
            "pfx_file": SimpleUploadedFile("c.pfx", make_pfx()), "pfx_password": "s3cret"})
        self.assertIn("pfx_file", r.context["form"].errors)

    def test_duplicate_between_cer_and_pfx(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
        pfx = make_pfx()
        cert_pem = load_pkcs12(pfx, b"s3cret").cert.certificate.public_bytes(Encoding.PEM)
        self.client.post("/certificates/new/", {
            "name": "A", "is_active": "on", "method": "store", "verify": "default",
            "certificate_file": SimpleUploadedFile("a.cer", cert_pem)})
        r = self.post_pfx(pfx, name="B")
        self.assertEqual(SigningCertificate.objects.count(), 1)

    def test_detail_page_shows_extracted_info(self):
        self.post_pfx(make_pfx())
        cert = SigningCertificate.objects.get()
        r = self.client.get(f"/certificates/{cert.pk}/")
        self.assertContains(r, "RSA 2048 bits")
        self.assertContains(r, cert.serial_number)


def AuditEventText():
    return [f"{e.target} {e.detail}" for e in AuditEvent.objects.all()]
