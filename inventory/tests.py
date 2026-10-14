import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth.models import Group, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from signing.models import SiteSettings

from . import parsing
from .models import InventoryCertificate

NOW = datetime.datetime.now(datetime.timezone.utc)


def build(cn="app.empresa.pt", san=None, eku=ExtendedKeyUsageOID.SERVER_AUTH, ca=False, days=200, ec_key=False,
          issuer_cn=None):
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - datetime.timedelta(days=max(1, -days + 1)))
         .not_valid_after(NOW + datetime.timedelta(days=days)))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(key, hashes.SHA256()), key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def pfx(cert, key, password=b"pw", chain=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"x", key, cert, chain, enc)


class ParsingTests(TestCase):
    def test_describe_tls_wildcard(self):
        cert, _ = build("*.empresa.pt", san=["*.empresa.pt", "empresa.pt"])
        d = parsing.describe(cert)
        self.assertEqual(d["cert_type"], "tls")
        self.assertTrue(d["is_wildcard"])
        self.assertEqual(d["san"].splitlines(), ["*.empresa.pt", "empresa.pt"])
        self.assertEqual(d["key_info"], "RSA 2048 bits")
        self.assertEqual(len(d["sha256"]), 64)

    def test_types(self):
        self.assertEqual(parsing.describe(build(eku=ExtendedKeyUsageOID.CODE_SIGNING)[0])["cert_type"], "code_signing")
        self.assertEqual(parsing.describe(build(eku=ExtendedKeyUsageOID.CLIENT_AUTH)[0])["cert_type"], "client")
        self.assertEqual(parsing.describe(build(eku=ExtendedKeyUsageOID.EMAIL_PROTECTION)[0])["cert_type"], "email")
        self.assertEqual(parsing.describe(build(eku=None, ca=True)[0])["cert_type"], "ca")
        self.assertEqual(parsing.describe(build(eku=None)[0])["cert_type"], "other")

    def test_ec_key(self):
        self.assertTrue(parsing.describe(build(ec_key=True)[0])["key_info"].startswith("EC"))

    def test_pem_bundle_and_key_detection(self):
        leaf, key = build("a.pt")
        ca, _ = build("CA", eku=None, ca=True)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        certs, has_key, fmt = parsing.load_certificates("x.pem", pem(leaf) + pem(ca) + key_pem, None)
        self.assertEqual((len(certs), has_key, fmt), (2, True, "pem"))

    def test_der(self):
        certs, has_key, fmt = parsing.load_certificates("x.cer", der(build()[0]), None)
        self.assertEqual((len(certs), has_key, fmt), (1, False, "der"))

    def test_p7b_pem_and_der(self):
        a, _ = build("a")
        b, _ = build("b")
        blob_pem = pkcs7.serialize_certificates([a, b], serialization.Encoding.PEM)
        blob_der = pkcs7.serialize_certificates([a, b], serialization.Encoding.DER)
        self.assertEqual(len(parsing.load_certificates("x.p7b", blob_pem, None)[0]), 2)
        self.assertEqual(len(parsing.load_certificates("x.p7b", blob_der, None)[0]), 2)

    def test_pfx_with_key_and_chain(self):
        leaf, key = build("a.pt")
        ca, _ = build("CA", eku=None, ca=True)
        certs, has_key, fmt = parsing.load_certificates("x.pfx", pfx(leaf, key, chain=[ca]), "pw")
        self.assertEqual((len(certs), has_key, fmt), (2, True, "pfx"))

    def test_pfx_needs_password(self):
        leaf, key = build()
        with self.assertRaises(parsing.PasswordNeeded):
            parsing.load_certificates("x.pfx", pfx(leaf, key), None)
        with self.assertRaises(parsing.ParseError):
            parsing.load_certificates("x.pfx", pfx(leaf, key), "wrong")

    def test_key_only_pem_rejected(self):
        _, key = build()
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(parsing.ParseError):
            parsing.load_certificates("x.key", key_pem, None)

    def test_garbage(self):
        with self.assertRaises(parsing.ParseError):
            parsing.load_certificates("x.txt", b"hello", None)


class InventoryViews(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("boss", password="x")
        self.admin.groups.add(Group.objects.get(name="Administradores"))
        self.client.force_login(self.admin)

    def upload(self, *files, **extra):
        data = {"files": [SimpleUploadedFile(n, c) for n, c in files], **extra}
        return self.client.post("/inventory/upload/", data)

    def test_default_groups_have_inventory_permissions(self):
        self.assertTrue(self.admin.has_perm("inventory.manage_inventory"))
        aud = User.objects.create_user("aud", password="x")
        aud.groups.add(Group.objects.get(name="Auditores"))
        self.assertTrue(aud.has_perm("inventory.view_inventorycertificate"))
        self.assertFalse(aud.has_perm("inventory.manage_inventory"))

    def test_permission_checks(self):
        u = User.objects.create_user("s", password="x")
        u.groups.add(Group.objects.get(name="Assinantes"))
        self.client.force_login(u)
        for url in ("/inventory/", "/inventory/upload/", "/inventory/export.csv"):
            self.assertEqual(self.client.get(url).status_code, 403, url)

    def test_upload_multiple_formats(self):
        a, ak = build("a.empresa.pt", san=["a.empresa.pt"])
        b, _ = build("b.empresa.pt")
        c, ck = build("c.empresa.pt")
        r = self.upload(("a.pfx", pfx(a, ak)), ("b.crt", der(b)), ("c.pem", pem(c)),
                        pfx_password="pw", server="VM-APP01", owner="Ana")
        self.assertEqual((r.context["n_added"], r.context["n_error"]), (3, 0))
        self.assertEqual(InventoryCertificate.objects.count(), 3)
        row = InventoryCertificate.objects.get(name="a.empresa.pt")
        self.assertEqual((row.server, row.owner, row.source_format, row.had_private_key), ("VM-APP01", "Ana", "pfx", True))
        self.assertContains(r, "continha a chave privada")

    def test_nothing_sensitive_is_stored(self):
        import os
        from django.conf import settings
        a, ak = build("secret.pt")
        self.upload(("a.pfx", pfx(a, ak, password=b"top-secret-pw")), pfx_password="top-secret-pw")
        row = InventoryCertificate.objects.get()
        for value in vars(row).values():
            self.assertNotIn("top-secret-pw", str(value))
        self.assertNotIn("PRIVATE KEY", " ".join(str(v) for v in vars(row).values()))
        self.assertFalse(any(f.endswith((".pfx", ".p12", ".key")) for _, _, fs in os.walk(settings.BASE_DIR / "static") for f in fs))

    def test_ca_skipped_unless_included(self):
        leaf, key = build("leaf.pt")
        ca, _ = build("Root CA", eku=None, ca=True)
        blob = pem(leaf) + pem(ca)
        r = self.upload(("bundle.pem", blob))
        self.assertEqual((r.context["n_added"], r.context["n_skipped"]), (1, 1))
        r = self.upload(("bundle.pem", blob), include_ca="on")
        self.assertEqual(InventoryCertificate.objects.count(), 2)

    def test_reupload_updates_and_keeps_notes(self):
        a, _ = build("a.pt")
        self.upload(("a.crt", der(a)))
        row = InventoryCertificate.objects.get()
        self.client.post(f"/inventory/{row.pk}/", {"name": "Site principal", "notes": "renovar com a DigiCert"})
        r = self.upload(("again.crt", der(a)), server="VM2")
        self.assertEqual((r.context["n_added"], r.context["n_updated"]), (0, 1))
        row.refresh_from_db()
        self.assertEqual((row.name, row.notes, row.server, row.source_filename), ("Site principal", "renovar com a DigiCert", "VM2", "again.crt"))
        self.assertEqual(InventoryCertificate.objects.count(), 1)

    def test_errors_reported_per_file(self):
        a, _ = build("ok.pt")
        leaf, key = build("p.pt")
        r = self.upload(("ok.crt", der(a)), ("bad.txt", b"nope"), ("p.pfx", pfx(leaf, key)))
        self.assertEqual((r.context["n_added"], r.context["n_error"]), (1, 2))
        msgs = " ".join(x.get("message", "") for x in r.context["results"])
        self.assertIn("palavra-passe", msgs)

    def test_no_files(self):
        r = self.client.post("/inventory/upload/", {})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(InventoryCertificate.objects.exists())

    def test_list_filters_and_stats(self):
        soon, _ = build("soon.pt", days=10)
        ok, _ = build("ok.pt", days=300)
        old, _ = build("old.pt", days=-5)
        self.upload(("a.crt", der(soon)), ("b.crt", der(ok)), ("c.crt", der(old)), server="VM1")
        r = self.client.get("/inventory/")
        self.assertEqual(r.context["stats"], {"total": 3, "ok": 1, "expiring": 1, "expired": 1})
        self.assertEqual([c.name for c in self.client.get("/inventory/?status=expired").context["certs"]], ["old.pt"])
        self.assertEqual([c.name for c in self.client.get("/inventory/?status=expiring").context["certs"]], ["soon.pt"])
        self.assertEqual([c.name for c in self.client.get("/inventory/?q=ok.pt").context["certs"]], ["ok.pt"])
        self.assertEqual(len(self.client.get("/inventory/?server=vm1").context["certs"]), 3)

    def test_search_by_san_and_fingerprint(self):
        a, _ = build("a.pt", san=["extra.empresa.pt"])
        self.upload(("a.crt", der(a)))
        self.assertEqual(len(self.client.get("/inventory/?q=extra.empresa").context["certs"]), 1)
        sha = InventoryCertificate.objects.get().sha256[:10]
        self.assertEqual(len(self.client.get(f"/inventory/?q={sha}").context["certs"]), 1)

    def test_csv_export_and_formula_injection(self):
        a, _ = build("=HYPERLINK(\"http://x\")")
        self.upload(("a.crt", der(a)))
        r = self.client.get("/inventory/export.csv")
        text = r.content.decode("utf-8-sig")
        self.assertIn("Nome;Tipo;Servidor", text)
        self.assertIn("'=HYPERLINK", text)
        self.assertNotIn(";=HYPERLINK", text)
        self.assertEqual(r["Content-Type"].split(";")[0], "text/csv")

    def test_detail_edit_delete(self):
        a, _ = build("a.pt", san=["a.pt", "www.a.pt"])
        self.upload(("a.crt", der(a)))
        row = InventoryCertificate.objects.get()
        r = self.client.get(f"/inventory/{row.pk}/")
        self.assertContains(r, "www.a.pt")
        self.client.post(f"/inventory/{row.pk}/", {"name": "n", "server": "S", "owner": "O", "purpose": "P", "notes": "x"})
        row.refresh_from_db()
        self.assertEqual((row.server, row.owner, row.purpose), ("S", "O", "P"))
        self.client.post(f"/inventory/{row.pk}/delete/")
        self.assertFalse(InventoryCertificate.objects.exists())

    def test_viewer_cannot_edit_or_delete(self):
        a, _ = build("a.pt")
        self.upload(("a.crt", der(a)))
        row = InventoryCertificate.objects.get()
        aud = User.objects.create_user("aud", password="x")
        aud.groups.add(Group.objects.get(name="Auditores"))
        self.client.force_login(aud)
        self.assertEqual(self.client.get(f"/inventory/{row.pk}/").status_code, 200)
        self.client.post(f"/inventory/{row.pk}/", {"name": "hack"})
        self.assertEqual(self.client.post(f"/inventory/{row.pk}/delete/").status_code, 403)
        row.refresh_from_db()
        self.assertEqual(row.name, "a.pt")

    def test_dashboard_inventory_block_and_nav(self):
        a, _ = build("soon.pt", days=5)
        self.upload(("a.crt", der(a)))
        r = self.client.get("/")
        self.assertEqual(r.context["inv"]["expiring"], 1)
        self.assertContains(r, "Inventário de certificados")
        self.assertContains(r, 'href="/inventory/"')

    def test_audit_events(self):
        from portal.models import AuditEvent
        a, _ = build("a.pt")
        self.upload(("a.crt", der(a)))
        self.assertTrue(AuditEvent.objects.filter(action="inventory_uploaded").exists())


class PermissionUpgradeTests(TestCase):
    def test_existing_default_groups_receive_new_permissions_once(self):
        from portal.permissions import ensure_default_groups

        admins = Group.objects.get(name="Administradores")
        for p in admins.permissions.filter(content_type__app_label="inventory"):
            admins.permissions.remove(p)
        s = SiteSettings.load()
        s.default_groups_version = 0
        s.save()
        ensure_default_groups()
        self.assertTrue(admins.permissions.filter(codename="manage_inventory").exists())
        # segunda vez: não volta a acrescentar o que alguém retirou de propósito
        admins.permissions.remove(admins.permissions.get(codename="manage_inventory"))
        ensure_default_groups()
        self.assertFalse(admins.permissions.filter(codename="manage_inventory").exists())
