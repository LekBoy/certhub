import datetime

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.utils import timezone

from signing.models import SigningCertificate, SigningRequest, SigningToken


def make_cert(name, days):
    return SigningCertificate.objects.create(
        name=name, thumbprint=name.encode().hex().upper().ljust(40, "0")[:40], subject=f"CN={name}",
        not_before=timezone.now() - datetime.timedelta(days=1), not_after=timezone.now() + datetime.timedelta(days=days),
    )


class PortalTests(TestCase):
    def setUp(self):
        self.signer = User.objects.create_user("ana", password="x")
        self.signer.groups.add(Group.objects.get(name="Assinantes"))
        self.other = User.objects.create_user("rui", password="x")
        self.auditor = User.objects.create_user("aud", password="x")
        self.auditor.groups.add(Group.objects.get(name="Auditores"))
        self.cert = make_cert("ok", 200)
        for u in (self.signer, self.other):
            SigningRequest.objects.create(user=u, certificate=self.cert, filename=f"{u.username}.dll", size=1,
                                          sha256_original="a" * 64, sha256_signed="b" * 64, status="ok")

    def test_groups_created(self):
        self.assertTrue(Group.objects.get(name="Assinantes").permissions.filter(codename="can_sign").exists())

    def test_login_page_and_redirect(self):
        self.assertContains(self.client.get("/login/"), "Entrar")
        self.assertRedirects(self.client.get("/"), "/login/?next=/")

    def test_certificate_status(self):
        self.assertEqual(self.cert.status, "ok")
        self.assertEqual(make_cert("soon", 10).status, "expiring")
        self.assertEqual(make_cert("old", -1).status, "expired")

    def test_dashboard_lists_expiring(self):
        make_cert("soon", 10)
        self.client.force_login(self.signer)
        r = self.client.get("/")
        self.assertEqual(r.context["stats"]["expiring"], 1)
        self.assertContains(r, "soon")

    def test_history_scoped_to_own_requests(self):
        self.client.force_login(self.signer)
        names = [r.filename for r in self.client.get("/history/").context["page"]]
        self.assertEqual(names, ["ana.dll"])

    def test_auditor_sees_all(self):
        self.client.force_login(self.auditor)
        self.assertEqual(len(self.client.get("/history/").context["page"]), 2)

    def test_history_filters(self):
        self.client.force_login(self.auditor)
        self.assertEqual(len(self.client.get("/history/?q=rui").context["page"]), 1)
        self.assertEqual(len(self.client.get("/history/?status=failed").context["page"]), 0)

    def test_tokens_require_signer_permission(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get("/tokens/").status_code, 403)

    def test_create_and_revoke_token(self):
        self.client.force_login(self.signer)
        r = self.client.post("/tokens/", {"name": "pipeline"})
        raw = r.context["raw_token"]
        token = SigningToken.objects.get()
        self.assertEqual(token.token_hash, SigningToken.hash_token(raw))
        self.assertNotContains(self.client.get("/tokens/"), raw)  # só aparece uma vez
        self.client.post(f"/tokens/{token.pk}/revoke/")
        token.refresh_from_db()
        self.assertFalse(token.valid)

    def test_cannot_revoke_other_users_token(self):
        t = SigningToken(user=self.signer, name="x")
        t.set_new_token()
        t.save()
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(f"/tokens/{t.pk}/revoke/").status_code, 404)

    def test_sign_page_json_error(self):
        self.client.force_login(self.signer)
        r = self.client.post("/sign/", {}, headers={"X-Requested-With": "fetch"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.json())

    def test_admin_user_actions(self):
        admin = User.objects.create_superuser("root", password="x")
        self.client.force_login(admin)
        self.client.post("/admin/auth/user/", {
            "action": "add_signers", "_selected_action": [self.other.pk]})
        self.assertTrue(self.other.groups.filter(name="Assinantes").exists())
        self.client.post("/admin/auth/user/", {"action": "deactivate", "_selected_action": [self.other.pk]})
        self.other.refresh_from_db()
        self.assertFalse(self.other.is_active)
