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
from .models import CertificateUsage, InventoryCertificate

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
                        pfx_password="pw", u_hostname="VM-APP01", u_ip_address="10.0.0.5", u_port="443",
                        u_application="Intranet", owner="Ana")
        self.assertEqual((r.context["n_added"], r.context["n_error"]), (3, 0))
        self.assertEqual(InventoryCertificate.objects.count(), 3)
        row = InventoryCertificate.objects.get(name="a.empresa.pt")
        self.assertEqual((row.owner, row.source_format, row.had_private_key), ("Ana", "pfx", True))
        usage = row.usages.get()
        self.assertEqual((usage.hostname, usage.ip_address, usage.port, usage.application),
                         ("VM-APP01", "10.0.0.5", 443, "Intranet"))
        self.assertEqual(usage.where, "VM-APP01 (10.0.0.5:443) · Intranet")
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
        r = self.upload(("again.crt", der(a)), u_hostname="VM2")
        self.assertEqual((r.context["n_added"], r.context["n_updated"]), (0, 1))
        row.refresh_from_db()
        self.assertEqual((row.name, row.notes, row.source_filename), ("Site principal", "renovar com a DigiCert", "again.crt"))
        self.assertEqual([u.hostname for u in row.usages.all()], ["VM2"])
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
        self.upload(("a.crt", der(soon)), ("b.crt", der(ok)), ("c.crt", der(old)), u_hostname="VM1")
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
        self.client.post(f"/inventory/{row.pk}/", {"name": "n", "owner": "O", "notes": "x"})
        row.refresh_from_db()
        self.assertEqual((row.name, row.owner, row.notes), ("n", "O", "x"))
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


class UsageTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("boss", password="x")
        self.admin.groups.add(Group.objects.get(name="Administradores"))
        self.client.force_login(self.admin)
        cert, _ = build("a.pt")
        self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("a.crt", der(cert))})
        self.cert = InventoryCertificate.objects.get()

    def add(self, **data):
        return self.client.post(f"/inventory/{self.cert.pk}/usages/add/", data)

    def test_several_usages_per_certificate(self):
        self.add(hostname="VM-WEB01", ip_address="10.0.0.10", port="443", application="Site público", environment="prod")
        self.add(hostname="VM-WEB02", ip_address="10.0.0.11", application="Site público")
        self.add(ip_address="2001:db8::1", application="API")
        self.assertEqual(self.cert.usages.count(), 3)
        summary = self.cert.usage_summary
        self.assertIn("2001:db8::1 · API", summary)  # sem servidor: mostra o IP
        self.assertTrue(summary.endswith("+1"))

    def test_requires_server_ip_or_application(self):
        r = self.add(notes="só notas", environment="dev")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(self.cert.usages.exists())
        self.assertContains(r, "pelo menos o servidor, o IP ou a aplicação")

    def test_ip_and_port_validation(self):
        self.add(hostname="x", ip_address="999.1.1.1")
        self.add(hostname="x", port="70000")
        self.add(hostname="x", port="0")
        self.assertFalse(self.cert.usages.exists())

    def test_edit_and_delete(self):
        self.add(hostname="VM1", ip_address="10.0.0.1")
        u = self.cert.usages.get()
        r = self.client.post(f"/inventory/usages/{u.pk}/", {"hostname": "VM9", "ip_address": "10.0.0.9", "port": "8443",
                                                         "application": "ERP", "environment": "staging"})
        self.assertRedirects(r, f"/inventory/{self.cert.pk}/")
        u.refresh_from_db()
        self.assertEqual((u.hostname, u.port, u.application), ("VM9", 8443, "ERP"))
        self.client.post(f"/inventory/usages/{u.pk}/delete/")
        self.assertFalse(self.cert.usages.exists())

    def test_deleting_certificate_removes_usages(self):
        self.add(hostname="VM1")
        self.client.post(f"/inventory/{self.cert.pk}/delete/")
        self.assertEqual(CertificateUsage.objects.count(), 0)

    def test_viewer_cannot_change_usages(self):
        self.add(hostname="VM1")
        u = self.cert.usages.get()
        aud = User.objects.create_user("aud", password="x")
        aud.groups.add(Group.objects.get(name="Auditores"))
        self.client.force_login(aud)
        self.assertEqual(self.client.post(f"/inventory/{self.cert.pk}/usages/add/", {"hostname": "evil"}).status_code, 403)
        self.assertEqual(self.client.post(f"/inventory/usages/{u.pk}/delete/").status_code, 403)
        self.assertEqual(self.client.get(f"/inventory/usages/{u.pk}/").status_code, 403)
        self.assertEqual(self.cert.usages.count(), 1)
        self.assertNotContains(self.client.get(f"/inventory/{self.cert.pk}/"), "Adicionar utilização")

    def test_search_and_filter_by_ip_and_application(self):
        self.add(hostname="VM-WEB01", ip_address="10.20.30.40", application="Intranet")
        other, _ = build("b.pt")
        self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("b.crt", der(other)), "u_hostname": "VM-DB",
                                               "u_ip_address": "10.99.0.1", "u_application": "ERP"})
        names = lambda qs: sorted(c.name for c in qs)  # noqa: E731
        self.assertEqual(names(self.client.get("/inventory/?q=10.20.30").context["certs"]), ["a.pt"])
        self.assertEqual(names(self.client.get("/inventory/?q=erp").context["certs"]), ["b.pt"])
        self.assertEqual(names(self.client.get("/inventory/?app=Intranet").context["certs"]), ["a.pt"])
        self.assertEqual(names(self.client.get("/inventory/?server=vm-db").context["certs"]), ["b.pt"])
        r = self.client.get("/inventory/")
        self.assertEqual(r.context["apps"], ["ERP", "Intranet"])
        self.assertContains(r, "VM-WEB01 (10.20.30.40) · Intranet")

    def test_same_certificate_on_two_servers_not_duplicated(self):
        cert, _ = build("shared.pt")
        blob = der(cert)
        for host in ("A", "B", "A"):
            self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("s.crt", blob), "u_hostname": host})
        shared = InventoryCertificate.objects.get(name="shared.pt")
        self.assertEqual(sorted(u.hostname for u in shared.usages.all()), ["A", "B"])

    def test_csv_lists_servers_ips_and_apps(self):
        self.add(hostname="VM1", ip_address="10.0.0.1", port="443", application="Intranet")
        self.add(hostname="VM2", ip_address="10.0.0.2", application="Intranet")
        text = self.client.get("/inventory/export.csv").content.decode("utf-8-sig")
        self.assertIn("VM1; VM2", text)
        self.assertIn("10.0.0.1:443; 10.0.0.2", text)
        self.assertEqual(text.count("Intranet"), 1)  # sem repetir

    def test_audit_trail(self):
        from portal.models import AuditEvent
        self.add(hostname="VM1")
        self.assertTrue(AuditEvent.objects.filter(action="inventory_usage_added").exists())

    def test_upload_with_several_servers_at_once(self):
        cert, _ = build("multi.pt")
        r = self.client.post("/inventory/upload/", {
            "files": SimpleUploadedFile("m.crt", der(cert)),
            "u_hostname": ["VM-A", "VM-B", ""], "u_ip_address": ["10.0.0.1", "10.0.0.2", ""],
            "u_port": ["443", "8443", ""], "u_application": ["Site", "Portal", ""], "u_environment": ["prod", "", ""]})
        self.assertEqual(r.context["n_added"], 1)
        c = InventoryCertificate.objects.get(name="multi.pt")
        self.assertEqual(sorted((u.hostname, u.port, u.application) for u in c.usages.all()),
                         [("VM-A", 443, "Site"), ("VM-B", 8443, "Portal")])  # a linha vazia é ignorada

    def test_each_certificate_in_the_upload_gets_all_rows(self):
        a, _ = build("a1.pt")
        b, _ = build("b1.pt")
        self.client.post("/inventory/upload/", {
            "files": [SimpleUploadedFile("a.crt", der(a)), SimpleUploadedFile("b.crt", der(b))],
            "u_hostname": ["X", "Y"], "u_ip_address": ["", ""], "u_port": ["", ""], "u_application": ["", ""],
            "u_environment": ["", ""]})
        self.assertEqual([c.usages.count() for c in InventoryCertificate.objects.filter(name__in=["a1.pt", "b1.pt"])], [2, 2])

    def test_invalid_row_keeps_entered_rows_and_shows_error(self):
        cert, _ = build("e.pt")
        r = self.client.post("/inventory/upload/", {
            "files": SimpleUploadedFile("e.crt", der(cert)),
            "u_hostname": ["OK", "BAD"], "u_ip_address": ["10.0.0.1", "999.9.9.9"], "u_port": ["", ""],
            "u_application": ["", ""], "u_environment": ["", ""]})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(InventoryCertificate.objects.filter(name="e.pt").exists())
        self.assertEqual([row["hostname"] for row in r.context["rows"]], ["OK", "BAD"])
        self.assertTrue(r.context["rows"][1]["errors"])
        self.assertContains(r, 'value="BAD"')

    def test_row_without_server_ip_or_application_is_rejected(self):
        cert, _ = build("f.pt")
        r = self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("f.crt", der(cert)), "u_environment": ["prod"]})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(InventoryCertificate.objects.filter(name="f.pt").exists())

    def test_no_usage_rows_is_fine(self):
        cert, _ = build("g.pt")
        r = self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("g.crt", der(cert))})
        self.assertEqual(r.context["n_added"], 1)
        self.assertFalse(CertificateUsage.objects.exists())

    def test_upload_rejects_invalid_ip(self):
        cert, _ = build("c.pt")
        r = self.client.post("/inventory/upload/", {"files": SimpleUploadedFile("c.crt", der(cert)), "u_ip_address": "nope"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(InventoryCertificate.objects.filter(name="c.pt").exists())


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
