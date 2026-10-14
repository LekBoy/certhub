import datetime
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth.models import Group, Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone

from . import service, signer
from .certinfo import CertificateError, parse_public_certificate
from .models import SigningCertificate, SigningRequest, SigningToken, SiteSettings
from .signer import SigningError


def make_cert(eku=ExtendedKeyUsageOID.CODE_SIGNING, days=365) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Code Signing")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def make_pfx(password=b"s3cret", eku=ExtendedKeyUsageOID.CODE_SIGNING, with_key=True) -> bytes:
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption, pkcs12

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Empresa PAD"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Empresa")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now)
               .not_valid_after(now + datetime.timedelta(days=200)))
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    enc = BestAvailableEncryption(password) if password else NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"x", key if with_key else None, cert, None, enc)


class CertInfoTests(TestCase):
    def test_pfx_reads_info_and_key_presence(self):
        from .certinfo import parse_pkcs12
        info = parse_pkcs12(make_pfx(), "s3cret")
        self.assertEqual(len(info["thumbprint"]), 40)
        self.assertIn("Empresa PAD", info["subject"])
        self.assertEqual(info["key_info"], "RSA 2048 bits")
        self.assertTrue(info["had_private_key"])
        self.assertEqual(info["source"], "pfx")

    def test_pfx_without_private_key(self):
        from .certinfo import parse_pkcs12
        self.assertFalse(parse_pkcs12(make_pfx(with_key=False, password=None), None)["had_private_key"])

    def test_pfx_wrong_password(self):
        from .certinfo import parse_pkcs12
        with self.assertRaises(CertificateError):
            parse_pkcs12(make_pfx(), "wrong")

    def test_pfx_requires_code_signing(self):
        from .certinfo import parse_pkcs12
        with self.assertRaises(CertificateError):
            parse_pkcs12(make_pfx(eku=ExtendedKeyUsageOID.SERVER_AUTH), "s3cret")

    def test_pfx_garbage(self):
        from .certinfo import parse_pkcs12
        with self.assertRaises(CertificateError):
            parse_pkcs12(b"not a pfx", "x")

    def test_accepts_code_signing(self):
        info = parse_public_certificate(make_cert())
        self.assertEqual(len(info["thumbprint"]), 40)

    def test_rejects_other_eku(self):
        with self.assertRaises(CertificateError):
            parse_public_certificate(make_cert(ExtendedKeyUsageOID.SERVER_AUTH))

    def test_rejects_no_eku(self):
        with self.assertRaises(CertificateError):
            parse_public_certificate(make_cert(None))

    def test_rejects_garbage(self):
        with self.assertRaises(CertificateError):
            parse_public_certificate(b"nope")




class SignApiTests(TestCase):
    def setUp(self):
        site = SiteSettings.load()
        site.verify_after_sign = False
        site.save()
        self.user = User.objects.create_user("dev", password="x")
        self.user.user_permissions.add(Permission.objects.get(codename="can_sign"))
        self.token = SigningToken(user=self.user, name="ci")
        self.raw = self.token.set_new_token()
        self.token.save()
        self.cert = SigningCertificate.objects.create(
            name="PAD", thumbprint="AB" * 20, subject="CN=x",
            not_before=timezone.now(), not_after=timezone.now() + datetime.timedelta(days=30),
        )
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.raw}"}

    def post(self, name="a.dll", **extra):
        return self.client.post("/api/sign/", {"file": SimpleUploadedFile(name, b"MZdata")}, **{**self.auth, **extra})

    def fake_run(self, args, **kw):
        if args[1] == "sign":
            open(args[-1], "ab").write(b"SIGNED")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_requires_token(self):
        r = self.client.post("/api/sign/", {"file": SimpleUploadedFile("a.dll", b"x")})
        self.assertEqual(r.status_code, 401)

    def test_expired_token_rejected(self):
        self.token.expires_at = timezone.now() - datetime.timedelta(days=1)
        self.token.save()
        self.assertEqual(self.post().status_code, 401)

    def test_user_without_permission_rejected(self):
        self.user.user_permissions.clear()
        self.assertEqual(self.post().status_code, 401)

    def test_signs_and_audits(self):
        with mock.patch("signing.signer.subprocess.run", side_effect=self.fake_run) as run:
            r = self.post()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"MZdataSIGNED")
        args = run.call_args.args[0]
        self.assertIn("/sha1", args)
        self.assertEqual(args[args.index("/fd") + 1], "SHA256")
        rec = SigningRequest.objects.get()
        self.assertEqual((rec.status, rec.user), ("ok", self.user))
        self.assertEqual(r["X-Signed-SHA256"], rec.sha256_signed)

    def test_timestamp_optional(self):
        for url, expected in (("", False), ("http://tsa.interna/ts", True)):
            site = SiteSettings.load()
            site.timestamp_url = url
            site.save()
            with mock.patch("signing.signer.subprocess.run", side_effect=self.fake_run) as run:
                self.post()
            args = run.call_args.args[0]
            self.assertEqual("/tr" in args, expected)
            if expected:
                self.assertEqual(args[args.index("/tr") + 1], url)

    def test_rejects_extension(self):
        self.assertEqual(self.post("a.txt").status_code, 400)
        self.assertFalse(SigningRequest.objects.exists())

    def test_expired_certificate_not_usable(self):
        self.cert.not_after = timezone.now() - datetime.timedelta(days=1)
        self.cert.save()
        self.assertEqual(self.post().status_code, 400)

    def test_signtool_failure_is_audited(self):
        with mock.patch("signing.service.signer.sign_file", side_effect=SigningError("boom")):
            r = self.post()
        self.assertEqual(r.status_code, 500)
        self.assertEqual(SigningRequest.objects.get().status, "failed")

    def test_web_page_requires_login(self):
        self.assertEqual(self.client.get("/sign/").status_code, 302)
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/sign/").status_code, 200)


class SigningMethodTests(TestCase):
    def make(self, **kw):
        return SigningCertificate.objects.create(
            name=kw.pop("name", "c"), thumbprint="AB" * 20, subject="CN=x", not_before=timezone.now(),
            not_after=timezone.now() + datetime.timedelta(days=30), **kw)

    def test_store_method(self):
        args = signer.build_command(self.make(), "f.dll")
        self.assertIn("/sm", args)
        self.assertEqual(args[args.index("/sha1") + 1], "AB" * 20)

    def test_keylocker_thumbprint_uses_user_store(self):
        args = signer.build_command(self.make(method="keylocker_thumbprint"), "f.dll")
        self.assertNotIn("/sm", args)
        self.assertNotIn("/s", args)
        self.assertEqual(args[-1], "f.dll")

    def test_keylocker_alias(self):
        cert = self.make(method="keylocker_alias", csp_name="DigiCert Signing Manager KSP",
                         keypair_alias="key-1", cert_file_path=r"C:\\certs\\a.cer")
        args = signer.build_command(cert, "f.dll")
        self.assertEqual(args[args.index("/csp") + 1], "DigiCert Signing Manager KSP")
        self.assertEqual(args[args.index("/kc") + 1], "key-1")
        self.assertEqual(args[args.index("/f") + 1], r"C:\\certs\\a.cer")

    def test_keylocker_alias_requires_fields(self):
        with self.assertRaises(signer.SigningError):
            signer.build_command(self.make(method="keylocker_alias"), "f.dll")

    def test_custom_command_placeholders(self):
        cert = self.make(method="custom", custom_command="{signtool}\nsign\n/sha1\n{thumbprint}\n{file}")
        site = SiteSettings.load()
        self.assertEqual(signer.build_command(cert, "f.dll", site),
                         [site.signtool_path, "sign", "/sha1", "AB" * 20, "f.dll"])

    def test_custom_command_unknown_placeholder(self):
        cert = self.make(method="custom", custom_command="x\n{nope}\n{file}")
        with self.assertRaises(signer.SigningError):
            signer.build_command(cert, "f.dll")

    def test_cert_timestamp_overrides_global(self):
        cert = self.make(timestamp_url="http://own/ts")
        args = signer.build_command(cert, "f.dll")
        self.assertEqual(args[args.index("/tr") + 1], "http://own/ts")


class AccessAndLimitTests(TestCase):
    def setUp(self):
        s = SiteSettings.load()
        s.verify_after_sign = False
        s.save()
        self.group = Group.objects.create(name="PAD")
        self.user = User.objects.create_user("dev", password="x")
        self.user.user_permissions.add(Permission.objects.get(codename="can_sign"))
        self.cert = SigningCertificate.objects.create(
            name="c", thumbprint="CD" * 20, subject="CN=x", not_before=timezone.now(),
            not_after=timezone.now() + datetime.timedelta(days=30))

    def upload(self):
        return SimpleUploadedFile("a.dll", b"MZ")

    def fake_run(self, args, **kw):
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_group_restriction(self):
        self.cert.allowed_groups.add(self.group)
        self.assertFalse(self.cert.usable_by(self.user))
        self.user.groups.add(self.group)
        self.assertTrue(self.cert.usable_by(self.user))

    def test_restricted_cert_rejected_on_sign(self):
        self.cert.allowed_groups.add(self.group)
        with self.assertRaises(service.RejectedUpload):
            service.sign_upload(self.upload(), self.user, self.cert, via_api=False)

    def test_usage_counts_only_successful_this_period(self):
        for st in ("ok", "ok", "failed"):
            SigningRequest.objects.create(user=self.user, certificate=self.cert, filename="a.dll", size=1,
                                          sha256_original="a" * 64, status=st)
        self.cert.annual_limit = 4
        self.assertEqual(self.cert.signed_in_period, 2)
        self.assertEqual(self.cert.usage_percent, 50)
        self.assertEqual(self.cert.limit_status, "ok")
        self.cert.annual_limit = 2
        self.assertEqual(self.cert.limit_status, "reached")
        self.cert.annual_limit = 5
        self.assertEqual(self.cert.limit_status, "ok")  # 40%

    def test_warning_at_80_percent(self):
        for _ in range(4):
            SigningRequest.objects.create(user=self.user, certificate=self.cert, filename="a.dll", size=1,
                                          sha256_original="a" * 64, status="ok")
        self.cert.annual_limit = 5
        self.assertEqual(self.cert.limit_status, "warning")

    def test_block_at_limit(self):
        SigningRequest.objects.create(user=self.user, certificate=self.cert, filename="a.dll", size=1,
                                      sha256_original="a" * 64, status="ok")
        self.cert.annual_limit = 1
        self.cert.save()
        with mock.patch("signing.signer.subprocess.run", side_effect=self.fake_run):
            service.sign_upload(self.upload(), self.user, self.cert, via_api=False)  # sem bloqueio: assina
            s = SiteSettings.load()
            s.block_at_limit = True
            s.save()
            with self.assertRaises(service.LimitReached):
                service.sign_upload(self.upload(), self.user, self.cert, via_api=False)

    def test_period_start_follows_subscription_anniversary(self):
        today = timezone.localdate()
        self.cert.subscription_start = datetime.date(today.year - 3, today.month, 1)
        self.assertEqual(self.cert.period_start, datetime.date(today.year, today.month, 1))

    def test_attention_reasons(self):
        self.cert.renewal_date = timezone.localdate() + datetime.timedelta(days=10)
        self.assertTrue(any("Renovação" in r for r in self.cert.attention))
