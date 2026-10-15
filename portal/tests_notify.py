import datetime
import os
from unittest import mock

from django.contrib.auth.models import Group, User
from django.core import mail
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from inventory.models import InventoryCertificate

from . import notify
from .models import NotificationLog, NotificationSettings

TODAY = datetime.date(2026, 6, 1)


def make_inv(n, days, name=None):
    exp = timezone.make_aware(datetime.datetime.combine(TODAY + datetime.timedelta(days=days), datetime.time(12)))
    return InventoryCertificate.objects.create(
        name=name or f"cert{n}", subject=f"CN=c{n}", issuer="CN=CA", serial_number=str(n), sha1="a" * 40,
        sha256=f"{n:064d}", not_before=exp - datetime.timedelta(days=365), not_after=exp)


def configure(**kw):
    cfg = NotificationSettings.load()
    vals = dict(enabled=True, recipients="ti@bca.cv", from_address="infrahub@bca.cv", smtp_host="smtp.local",
                smtp_security="none", base_url="https://infrahub.bca.cv")
    vals.update(kw)
    for k, v in vals.items():
        setattr(cfg, k, v)
    cfg.save()
    return cfg


class ThresholdTests(TestCase):
    def test_threshold_for(self):
        t = [30, 15, 7, 3, 1]
        f = notify.threshold_for
        self.assertIsNone(f(31, t, True))
        self.assertEqual(f(30, t, True), 30)
        self.assertEqual(f(20, t, True), 30)
        self.assertEqual(f(7, t, True), 7)
        self.assertEqual(f(0, t, True), 1)
        self.assertEqual(f(-2, t, True), -1)
        self.assertIsNone(f(-2, t, False))


class RunAlertsTests(TestCase):
    def setUp(self):
        configure()

    def test_sends_one_digest_with_links(self):
        make_inv(1, 5)
        make_inv(2, 100)
        make_inv(3, -3)
        res = notify.run_alerts(today=TODAY)
        self.assertEqual(res["alerts"], 2)
        self.assertEqual(len(mail.outbox), 1)
        m = mail.outbox[0]
        self.assertEqual(m.to, ["ti@bca.cv"])
        self.assertIn("cert1", m.body)
        self.assertNotIn("cert2", m.body)
        self.assertIn("https://infrahub.bca.cv/certhub/inventory/", m.body)
        self.assertIn("expirado", m.subject)

    def test_only_once_per_threshold_then_next_threshold(self):
        make_inv(1, 10)
        notify.run_alerts(today=TODAY)
        notify.run_alerts(today=TODAY)
        self.assertEqual(len(mail.outbox), 1)
        notify.run_alerts(today=TODAY + datetime.timedelta(days=4))  # faltam 6 -> limiar 7
        self.assertEqual(len(mail.outbox), 2)

    def test_renewal_resets(self):
        c = make_inv(1, 5)
        notify.run_alerts(today=TODAY)
        c.not_after += datetime.timedelta(days=360)
        c.save()
        self.assertEqual(notify.run_alerts(today=TODAY)["alerts"], 0)
        later = TODAY + datetime.timedelta(days=362)
        notify.run_alerts(today=later)
        self.assertEqual(len(mail.outbox), 2)

    def test_disabled_and_dry_run_send_nothing(self):
        make_inv(1, 5)
        res = notify.run_alerts(dry_run=True, today=TODAY)
        self.assertEqual(res["alerts"], 1)
        self.assertEqual(mail.outbox, [])
        configure(enabled=False)
        self.assertTrue(notify.run_alerts(today=TODAY)["skipped"])
        self.assertEqual(mail.outbox, [])

    def test_failure_is_logged_and_retried(self):
        make_inv(1, 5)
        with mock.patch.object(notify, "_send_smtp", side_effect=notify.SendError("boom")):
            res = notify.run_alerts(today=TODAY)
        self.assertEqual(res["error"], "boom")
        self.assertFalse(NotificationLog.objects.get().ok)
        notify.run_alerts(today=TODAY)
        self.assertEqual(len(mail.outbox), 1)

    def test_html_escapes_names(self):
        make_inv(1, 5, name="<script>x</script>")
        notify.run_alerts(today=TODAY)
        html = mail.outbox[0].alternatives[0][0]
        self.assertNotIn("<script>", html)

    def test_graph_transport(self):
        configure(transport="graph", graph_tenant_id="t", graph_client_id="c")
        make_inv(1, 5)
        calls = []

        def fake(url, data, headers):
            calls.append(url)
            return {"access_token": "tok"}

        with mock.patch.dict(os.environ, {notify.GRAPH_SECRET_ENV: "s3cret"}), \
                mock.patch.object(notify, "_http_json", fake):
            res = notify.run_alerts(today=TODAY)
        self.assertTrue(res["sent"])
        self.assertIn("/token", calls[0])
        self.assertTrue(calls[1].endswith("/users/infrahub%40bca.cv/sendMail"))

    def test_graph_without_secret_fails(self):
        configure(transport="graph", graph_tenant_id="t", graph_client_id="c")
        make_inv(1, 5)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(notify.GRAPH_SECRET_ENV, None)
            self.assertTrue(notify.run_alerts(today=TODAY)["error"])


class CommandTests(TestCase):
    def setUp(self):
        configure()

    def test_command_dry_run_and_test(self):
        make_inv(1, 5)
        call_command("send_expiry_alerts", "--dry-run")
        self.assertEqual(mail.outbox, [])
        call_command("send_expiry_alerts", "--test")
        self.assertEqual(len(mail.outbox), 1)

    def test_test_without_recipients_errors(self):
        configure(recipients="")
        with self.assertRaises(CommandError):
            call_command("send_expiry_alerts", "--test")


class NotificationViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("boss", password="x")
        self.admin.groups.add(Group.objects.get(name="Administradores"))
        self.client.force_login(self.admin)

    def test_admin_group_gets_permission_and_page_renders(self):
        self.assertTrue(self.admin.has_perm("portal.manage_notifications"))
        r = self.client.get("/manage/notifications/")
        self.assertContains(r, "Notificações por e-mail")

    def test_other_users_forbidden(self):
        u = User.objects.create_user("s", password="x")
        u.groups.add(Group.objects.get(name="Assinantes"))
        self.client.force_login(u)
        self.assertEqual(self.client.get("/manage/notifications/").status_code, 403)

    def test_save_validates_and_normalises(self):
        data = {"enabled": "", "recipients": "a@b.cv; c@d.cv", "thresholds": "7, 30,1", "base_url": "https://x.cv/",
                "transport": "smtp", "from_address": "", "from_name": "InfraHub", "smtp_port": 587,
                "smtp_security": "starttls"}
        r = self.client.post("/manage/notifications/", data)
        self.assertEqual(r.status_code, 302)
        cfg = NotificationSettings.load()
        self.assertEqual(cfg.thresholds, "30,7,1")
        self.assertEqual(cfg.base_url, "https://x.cv")
        bad = self.client.post("/manage/notifications/", {**data, "recipients": "nao-e-email", "thresholds": "x"})
        self.assertEqual(bad.status_code, 200)

    def test_enabling_requires_config(self):
        r = self.client.post("/manage/notifications/", {
            "enabled": "on", "recipients": "", "thresholds": "30", "transport": "smtp", "from_name": "I",
            "smtp_port": 587, "smtp_security": "starttls"})
        self.assertEqual(r.status_code, 200)

    def test_secrets_never_shown(self):
        with mock.patch.dict(os.environ, {notify.SMTP_PASSWORD_ENV: "hunter2-secret"}):
            r = self.client.get("/manage/notifications/")
        self.assertNotContains(r, "hunter2-secret")
        self.assertContains(r, "Definida")

    def test_test_button(self):
        configure()
        r = self.client.post("/manage/notifications/test/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(self.client.get("/manage/notifications/test/").status_code, 405)
