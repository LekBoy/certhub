import datetime
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth.models import Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone

from .certinfo import CertificateError, parse_public_certificate
from .models import SigningCertificate, SigningRequest, SigningToken
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


class CertInfoTests(TestCase):
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




@override_settings(SIGN_VERIFY=False)
class SignApiTests(TestCase):
    def setUp(self):
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
