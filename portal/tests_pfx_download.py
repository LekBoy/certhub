import os
from unittest import mock

from cryptography.fernet import Fernet
from django.contrib.auth.models import Group, Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from signing import filecrypt
from signing.models import SigningCertificate
from signing.tests import make_pfx

from .models import AuditEvent

KEY = Fernet.generate_key().decode()


def with_key(test):
    return mock.patch.dict(os.environ, {filecrypt.ENV_VAR: KEY})(test)


class FileCryptTests(TestCase):
    @with_key
    def test_roundtrip_and_not_plaintext(self):
        data = b"-----secret key material-----"
        token = filecrypt.encrypt(data)
        self.assertNotIn(b"secret key material", token)
        self.assertEqual(filecrypt.decrypt(token), data)

    @with_key
    def test_key_rotation(self):
        old = filecrypt.encrypt(b"x")
        new_key = Fernet.generate_key().decode()
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: f"{new_key},{KEY}"}):
            self.assertEqual(filecrypt.decrypt(old), b"x")  # a chave antiga ainda decifra

    def test_missing_or_wrong_key(self):
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: ""}):
            self.assertFalse(filecrypt.is_configured())
            with self.assertRaises(filecrypt.FileCryptError):
                filecrypt.encrypt(b"x")
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: KEY}):
            token = filecrypt.encrypt(b"x")
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: Fernet.generate_key().decode()}):
            with self.assertRaises(filecrypt.FileCryptError):
                filecrypt.decrypt(token)


class PfxDownloadBase(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("boss", password="x")
        self.admin.groups.add(Group.objects.get(name="Administradores"))
        self.pfx = make_pfx()

    def register(self, **extra):
        self.client.force_login(self.admin)
        data = {"name": "Assinatura interna", "is_active": "on", "method": "store", "store_name": "My",
                "machine_store": "on", "verify": "default", "pfx_file": SimpleUploadedFile("c.pfx", self.pfx),
                "pfx_password": "s3cret", "store_pfx": "on"}
        data.update(extra)
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: KEY}):
            r = self.client.post("/certhub/certificates/new/", data, follow=True)
        return r, SigningCertificate.objects.first()

    def dev(self, name, *groups, download_perm=True, sign_perm=True):
        u = User.objects.create_user(name, password="x")
        g = Group.objects.create(name=f"g-{name}")
        codes = [("portal", "access_certhub")]
        if sign_perm:
            codes.append(("signing", "can_sign"))
        if download_perm:
            codes.append(("signing", "download_pfx"))
        for app, code in codes:
            g.permissions.add(Permission.objects.get(content_type__app_label=app, codename=code))
        u.groups.add(g, *groups)
        return u, g

    def download(self, user, cert):
        self.client.force_login(user)
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: KEY}):
            return self.client.post(f"/certhub/certificates/{cert.pk}/download/")


class StorePfxTests(PfxDownloadBase):
    def test_store_encrypts_and_never_keeps_plaintext_or_password(self):
        _, cert = self.register()
        self.assertTrue(cert.has_pfx)
        self.assertEqual(cert.pfx_filename, "Assinatura_interna.pfx")
        self.assertNotIn(self.pfx[:40], bytes(cert.pfx_encrypted))
        for value in vars(cert).values():
            self.assertNotIn("s3cret", str(value))
        self.assertNotIn("s3cret", " ".join(AuditEvent.objects.values_list("detail", flat=True)))

    def test_default_is_not_stored(self):
        _, cert = self.register(store_pfx="")
        self.assertFalse(cert.has_pfx)

    def test_store_needs_private_key_and_server_key(self):
        self.pfx = make_pfx(with_key=False)
        r, cert = self.register()
        self.assertIsNone(cert)
        self.assertContains(r, "não contém a chave privada")
        self.pfx = make_pfx()
        self.client.force_login(self.admin)
        with mock.patch.dict(os.environ, {filecrypt.ENV_VAR: ""}):
            r = self.client.post("/certhub/certificates/new/", {
                "name": "x", "is_active": "on", "method": "store", "store_name": "My", "verify": "default",
                "pfx_file": SimpleUploadedFile("c.pfx", self.pfx), "pfx_password": "s3cret", "store_pfx": "on"})
        self.assertFalse(SigningCertificate.objects.exists())
        self.assertContains(r, filecrypt.ENV_VAR)

    def test_store_needs_pfx_upload(self):
        self.client.force_login(self.admin)
        from signing.tests import make_cert
        r = self.client.post("/certhub/certificates/new/", {
            "name": "x", "is_active": "on", "method": "store", "store_name": "My", "verify": "default",
            "certificate_file": SimpleUploadedFile("a.cer", make_cert()), "store_pfx": "on"})
        self.assertContains(r, "envie o .pfx")

    def test_remove_stored_pfx(self):
        _, cert = self.register()
        self.client.post(f"/certhub/certificates/{cert.pk}/", {
            "name": cert.name, "is_active": "on", "method": "store", "store_name": "My", "machine_store": "on",
            "verify": "default", "remove_pfx": "on"})
        cert.refresh_from_db()
        self.assertFalse(cert.has_pfx)


class DownloadAccessTests(PfxDownloadBase):
    def setUp(self):
        super().setUp()
        _, self.cert = self.register()

    def test_group_and_permission_both_needed(self):
        dev, group = self.dev("ana")
        self.assertEqual(self.download(dev, self.cert).status_code, 403)  # grupo não escolhido no certificado
        self.cert.download_groups.add(group)
        r = self.download(dev, self.cert)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, self.pfx)  # o ficheiro original, decifrado
        self.assertIn("Assinatura_interna.pfx", r["Content-Disposition"])
        self.assertEqual(r["Cache-Control"], "no-store")

    def test_group_without_module_permission_is_denied(self):
        dev, group = self.dev("bia", download_perm=False)
        self.cert.download_groups.add(group)
        self.assertEqual(self.download(dev, self.cert).status_code, 403)

    def test_empty_download_groups_means_nobody_except_superuser(self):
        dev, _ = self.dev("caio")
        self.assertFalse(self.cert.download_groups.exists())
        self.assertEqual(self.download(dev, self.cert).status_code, 403)
        root = User.objects.create_superuser("root", password="x")
        self.assertEqual(self.download(root, self.cert).status_code, 200)

    def test_sign_and_download_are_independent(self):
        sign_only, g1 = self.dev("dora", download_perm=False)
        download_only, g2 = self.dev("eli", sign_perm=False)
        both, g3 = self.dev("fabio")
        self.cert.allowed_groups.set([g1, g3])
        self.cert.download_groups.set([g2, g3])
        self.assertTrue(self.cert.usable_by(sign_only) and not self.cert.can_download(sign_only))
        self.assertTrue(self.cert.can_download(download_only) and not self.cert.usable_by(download_only))
        self.assertTrue(self.cert.usable_by(both) and self.cert.can_download(both))

    def test_inactive_certificate_cannot_be_downloaded(self):
        dev, group = self.dev("gil")
        self.cert.download_groups.add(group)
        self.cert.is_active = False
        self.cert.save()
        self.assertEqual(self.download(dev, self.cert).status_code, 403)

    def test_only_post_and_login_required(self):
        dev, group = self.dev("hugo")
        self.cert.download_groups.add(group)
        self.client.force_login(dev)
        self.assertEqual(self.client.get(f"/certhub/certificates/{self.cert.pk}/download/").status_code, 405)
        self.client.logout()
        r = self.client.post(f"/certhub/certificates/{self.cert.pk}/download/")
        self.assertEqual(r.status_code, 302)

    def test_downloads_and_denials_are_audited(self):
        dev, group = self.dev("ines")
        self.download(dev, self.cert)
        self.cert.download_groups.add(group)
        self.download(dev, self.cert)
        actions = list(AuditEvent.objects.filter(username="ines").order_by("id").values_list("action", flat=True))
        self.assertEqual(actions, ["certificate_pfx_download_denied", "certificate_pfx_downloaded"])

    def test_list_shows_button_only_to_allowed(self):
        dev, group = self.dev("jose")
        self.client.force_login(dev)
        url = f"/certhub/certificates/{self.cert.pk}/download/"
        self.assertNotContains(self.client.get("/certhub/certificates/"), url)
        self.cert.download_groups.add(group)
        r = self.client.get("/certhub/certificates/")
        self.assertContains(r, url)
        self.assertContains(r, "Descarregar .pfx")

    def test_admin_group_gets_the_permission(self):
        self.assertTrue(self.admin.has_perm("signing.download_pfx"))
        self.assertFalse(Group.objects.get(name="Assinantes").permissions.filter(codename="download_pfx").exists())
