import datetime
from unittest import mock

from django.contrib.auth.models import Group, Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone

from signing.models import SigningCertificate, SigningToken, SiteSettings

from . import modules
from .models import AuditEvent, ModuleState
from .permissions import ensure_default_groups


def perms(*codenames):
    return Permission.objects.filter(codename__in=codenames)


def make_user(name, *codenames, groups=()):
    u = User.objects.create_user(name, password="x")
    u.user_permissions.add(*perms(*codenames))
    for g in groups:
        u.groups.add(Group.objects.get(name=g))
    return u


class AccessRuleTests(TestCase):
    def test_permissions_without_module_access_have_no_effect(self):
        pedro = make_user("pedro", "can_sign", "view_all_history", "manage_inventory")
        for code in ("signing.can_sign", "portal.view_all_history", "inventory.manage_inventory"):
            self.assertFalse(pedro.has_perm(code), code)

    def test_with_access_the_inner_permissions_apply(self):
        pedro = make_user("pedro", "access_certhub", "can_sign")
        self.assertTrue(pedro.has_perm("signing.can_sign"))
        self.assertFalse(pedro.has_perm("portal.view_all_history"))  # não tem esta

    def test_access_alone_grants_nothing_else(self):
        pedro = make_user("pedro", "access_certhub")
        self.assertTrue(pedro.has_perm("portal.access_certhub"))
        for code in ("signing.can_sign", "portal.manage_certificates", "inventory.view_inventorycertificate"):
            self.assertFalse(pedro.has_perm(code), code)

    def test_platform_permissions_do_not_need_module_access(self):
        admin = make_user("adm", "manage_users", "view_audit")
        self.assertTrue(admin.has_perm("portal.manage_users"))
        self.assertTrue(admin.has_perm("portal.view_audit"))

    def test_access_through_group(self):
        pedro = make_user("pedro", groups=["Assinantes"])
        self.assertTrue(pedro.has_perm("signing.can_sign"))

    def test_superuser_has_access(self):
        root = User.objects.create_superuser("root", password="x")
        self.assertTrue(modules.user_can_access(root, modules.get("certhub")))

    def test_inactive_and_anonymous_have_no_access(self):
        from django.contrib.auth.models import AnonymousUser
        u = make_user("x", "access_certhub")
        u.is_active = False
        self.assertFalse(modules.user_can_access(u, modules.get("certhub")))
        self.assertFalse(modules.user_can_access(AnonymousUser(), modules.get("certhub")))

    def test_registry(self):
        m = modules.get("certhub")
        self.assertIs(modules.module_for_permission("signing.can_sign"), m)
        self.assertIs(modules.module_for_permission("portal.access_certhub"), m)
        self.assertIsNone(modules.module_for_permission("portal.manage_users"))
        self.assertIs(modules.module_for_path("/certhub/inventory/"), m)
        self.assertIsNone(modules.module_for_path("/manage/users/"))


class PagesAndMenuTests(TestCase):
    def test_no_access_means_403_on_every_module_url(self):
        pedro = make_user("pedro", "can_sign", "manage_certificates", "view_inventorycertificate")  # sem acesso
        self.client.force_login(pedro)
        for url in ("/certhub/sign/", "/certhub/certificates/", "/certhub/history/", "/certhub/tokens/",
                    "/certhub/inventory/", "/certhub/certificates/new/", "/certhub/settings/"):
            self.assertEqual(self.client.get(url).status_code, 403, url)

    def test_access_without_permissions_sees_only_the_basics(self):
        pedro = make_user("pedro", "access_certhub")
        self.client.force_login(pedro)
        self.assertEqual(self.client.get("/certhub/certificates/").status_code, 200)
        self.assertEqual(self.client.get("/certhub/history/").status_code, 200)
        for url in ("/certhub/sign/", "/certhub/tokens/", "/certhub/inventory/", "/certhub/certificates/new/",
                    "/certhub/settings/", "/certhub/tokens/all/"):
            self.assertEqual(self.client.get(url).status_code, 403, url)

    def test_menu_follows_access_and_permissions(self):
        pedro = make_user("pedro", "access_certhub", "can_sign")
        self.client.force_login(pedro)
        r = self.client.get("/")
        labels = [i["label"] for s in r.context["nav_sections"] for i in s["items"]]
        self.assertEqual(labels, ["Assinar ficheiro", "Certificados de assinatura", "Histórico", "Tokens de API"])
        self.assertEqual(r.context["nav_admin"], [])
        self.assertEqual(r.context["nav_sections"][0]["module"].name, "CertHub")

    def test_user_without_access_sees_no_module_and_a_hint(self):
        self.client.force_login(make_user("pedro", "can_sign"))
        r = self.client.get("/")
        self.assertEqual(r.context["nav_sections"], [])
        self.assertContains(r, "Ainda não tem acesso a nenhum módulo")

    def test_admin_menu_follows_platform_permissions(self):
        self.client.force_login(make_user("adm", "manage_users", "manage_modules", "view_audit"))
        r = self.client.get("/")
        self.assertEqual([i["label"] for i in r.context["nav_admin"]], ["Utilizadores", "Módulos", "Auditoria"])
        self.assertEqual(r.context["nav_sections"], [])

    def test_most_specific_menu_item_is_active(self):
        root = User.objects.create_superuser("root", password="x")
        self.client.force_login(root)
        r = self.client.get("/certhub/tokens/all/")
        active = [i["label"] for s in r.context["nav_sections"] for i in s["items"] if i["active"]]
        self.assertEqual(active, ["Todos os tokens"])
        r = self.client.get("/certhub/tokens/")
        active = [i["label"] for s in r.context["nav_sections"] for i in s["items"] if i["active"]]
        self.assertEqual(active, ["Tokens de API"])

    def test_anonymous_is_sent_to_login_not_403(self):
        r = self.client.get("/certhub/history/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login/", r["Location"])

    def test_old_root_urls_are_gone_and_api_url_is_stable(self):
        root = User.objects.create_superuser("root", password="x")
        self.client.force_login(root)
        for url in ("/sign/", "/certificates/", "/history/", "/inventory/"):
            self.assertEqual(self.client.get(url).status_code, 404, url)
        self.assertEqual(self.client.post("/api/sign/").status_code, 401)  # existe, pede token

    def test_dashboard_shows_certhub_block_only_with_access(self):
        self.client.force_login(make_user("pedro", "access_certhub", "can_sign"))
        self.assertContains(self.client.get("/"), "Certificados válidos")
        self.client.force_login(make_user("outro", "can_sign"))
        self.assertNotContains(self.client.get("/"), "Certificados válidos")


class ApiAccessTests(TestCase):
    def setUp(self):
        s = SiteSettings.load()
        s.verify_after_sign = False
        s.save()
        self.cert = SigningCertificate.objects.create(
            name="c", thumbprint="AB" * 20, subject="CN=x", not_before=timezone.now(),
            not_after=timezone.now() + datetime.timedelta(days=30))

    def call(self, user):
        t = SigningToken(user=user, name="ci")
        raw = t.set_new_token()
        t.save()
        ok = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("signing.signer.subprocess.run", return_value=ok):
            return self.client.post("/api/sign/", {"file": SimpleUploadedFile("a.dll", b"MZ")},
                                    HTTP_AUTHORIZATION=f"Bearer {raw}")

    def test_token_of_user_without_module_access_is_rejected(self):
        self.assertEqual(self.call(make_user("a", "can_sign")).status_code, 401)

    def test_token_of_user_with_access_works(self):
        self.assertEqual(self.call(make_user("b", "can_sign", "access_certhub")).status_code, 200)

    def test_removing_access_cuts_the_api_immediately(self):
        u = make_user("c", "can_sign", "access_certhub")
        self.assertEqual(self.call(u).status_code, 200)
        u.user_permissions.remove(*perms("access_certhub"))
        self.assertEqual(self.call(User.objects.get(pk=u.pk)).status_code, 401)


class ModulesPageTests(TestCase):
    def setUp(self):
        self.admin = make_user("adm", "manage_modules", "manage_users", groups=[])
        self.client.force_login(self.admin)

    def test_requires_permission(self):
        self.client.force_login(make_user("x", "access_certhub"))
        self.assertEqual(self.client.get("/manage/modules/").status_code, 403)

    def test_lists_modules_with_users_and_groups(self):
        make_user("a", groups=["Assinantes"])
        make_user("b", "access_certhub")
        r = self.client.get("/manage/modules/")
        row = r.context["rows"][0]
        self.assertEqual(row["module"].key, "certhub")
        self.assertEqual(row["n_users"], 2)  # a (pelo grupo) e b (direto); o administrador não tem acesso ao módulo
        self.assertIn("Assinantes", [g.name for g in row["groups"]])

    def test_disable_and_enable_module(self):
        root = User.objects.create_superuser("root", password="x")
        pedro = make_user("pedro", "access_certhub", "can_sign")
        self.client.post("/manage/modules/certhub/toggle/")
        self.assertFalse(ModuleState.objects.get(key="certhub").enabled)
        self.assertTrue(AuditEvent.objects.filter(action="module_disabled").exists())
        # ninguém entra, nem o superadministrador; a API também pára
        for user in (root, pedro):
            self.client.force_login(user)
            self.assertEqual(self.client.get("/certhub/history/").status_code, 403)
            self.assertEqual(self.client.get("/").context["nav_sections"], [])
        t = SigningToken(user=pedro, name="ci")
        raw = t.set_new_token()
        t.save()
        r = self.client.post("/api/sign/", {"file": SimpleUploadedFile("a.dll", b"MZ")}, HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(r.status_code, 401)
        # voltar a ligar
        self.client.force_login(self.admin)
        self.client.post("/manage/modules/certhub/toggle/")
        self.assertTrue(ModuleState.objects.get(key="certhub").enabled)
        self.client.force_login(pedro)
        self.assertEqual(self.client.get("/certhub/history/").status_code, 200)

    def test_unknown_module_is_404(self):
        self.assertEqual(self.client.post("/manage/modules/nope/toggle/").status_code, 404)

    def test_disabled_module_is_hidden_from_open_button(self):
        self.client.post("/manage/modules/certhub/toggle/")
        self.assertNotContains(self.client.get("/manage/modules/"), "Abrir módulo")


class GroupFormTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser("root", password="x")
        self.client.force_login(self.root)

    def test_form_is_a_dual_list_with_module_access_and_platform_options(self):
        r = self.client.get("/manage/groups/new/")
        self.assertContains(r, 'class="duallist"', count=2)  # permissões e membros
        self.assertContains(r, "Acesso ao módulo CertHub")
        self.assertContains(r, 'optgroup label="Plataforma"')
        self.assertContains(r, "Gerir módulos")
        self.assertContains(r, 'value="portal.access_certhub"')
        self.assertContains(r, 'name="perms"')
        self.assertContains(r, 'name="members"')
        self.assertEqual(r.context["perm_chosen"], [])  # grupo novo: nada escolhido

    def test_inner_permissions_without_access_are_not_saved(self):
        self.client.post("/manage/groups/new/", {"name": "Sem acesso", "perms": ["signing.can_sign", "portal.manage_users"]})
        g = Group.objects.get(name="Sem acesso")
        self.assertEqual({p.codename for p in g.permissions.all()}, {"manage_users"})  # a de plataforma fica

    def test_with_access_everything_is_saved(self):
        self.client.post("/manage/groups/new/", {"name": "Com acesso", "perms": ["portal.access_certhub", "signing.can_sign"]})
        g = Group.objects.get(name="Com acesso")
        self.assertEqual({p.codename for p in g.permissions.all()}, {"access_certhub", "can_sign"})

    def test_edit_shows_current_state(self):
        g = Group.objects.get(name="Assinantes")
        r = self.client.get(f"/manage/groups/{g.pk}/")
        chosen = [o["value"] for grp in r.context["perm_chosen"] for o in grp["options"]]
        available = [o["value"] for grp in r.context["perm_available"] for o in grp["options"]]
        self.assertEqual(sorted(chosen), ["portal.access_certhub", "signing.can_sign"])
        self.assertIn("portal.manage_users", available)
        self.assertEqual(set(chosen) & set(available), set())
        self.assertIn("portal.access_certhub", r.context["selected"])

    def test_members_are_split_between_available_and_chosen(self):
        g = Group.objects.get(name="Assinantes")
        member = make_user("membro", groups=["Assinantes"])
        other = make_user("outro")
        r = self.client.get(f"/manage/groups/{g.pk}/")
        chosen = [o["label"] for grp in r.context["member_chosen"] for o in grp["options"]]
        available = [o["label"] for grp in r.context["member_available"] for o in grp["options"]]
        self.assertTrue(any(c.startswith("membro") for c in chosen))
        self.assertTrue(any(a.startswith("outro") for a in available))

    def test_form_redisplays_chosen_items_after_an_error(self):
        r = self.client.post("/manage/groups/new/", {"name": "", "perms": ["portal.access_certhub", "signing.can_sign"]})
        self.assertEqual(r.status_code, 200)
        chosen = [o["value"] for grp in r.context["perm_chosen"] for o in grp["options"]]
        self.assertEqual(sorted(chosen), ["portal.access_certhub", "signing.can_sign"])

    def test_dual_list_script_is_served(self):
        from django.contrib.staticfiles import finders
        self.assertTrue(finders.find("js/dual-list.js"))


class UpgradeTests(TestCase):
    def test_existing_groups_with_module_permissions_get_access(self):
        custom = Group.objects.create(name="Equipa PAD")
        custom.permissions.add(*perms("can_sign"))
        unrelated = Group.objects.create(name="So plataforma")
        unrelated.permissions.add(*perms("manage_users"))
        direct = make_user("direto", "view_all_history")
        s = SiteSettings.load()
        s.default_groups_version = 2  # estado de uma instalação anterior
        s.save()
        ensure_default_groups()
        self.assertTrue(custom.permissions.filter(codename="access_certhub").exists())
        self.assertFalse(unrelated.permissions.filter(codename="access_certhub").exists())
        self.assertTrue(direct.user_permissions.filter(codename="access_certhub").exists())
        self.assertEqual(SiteSettings.load().default_groups_version, 3)

    def test_default_groups_receive_new_permissions_without_losing_any(self):
        assinantes = Group.objects.get(name="Assinantes")
        assinantes.permissions.remove(*perms("access_certhub"))
        s = SiteSettings.load()
        s.default_groups_version = 2
        s.save()
        ensure_default_groups()
        self.assertTrue(assinantes.permissions.filter(codename="access_certhub").exists())
        self.assertTrue(assinantes.permissions.filter(codename="can_sign").exists())

    def test_runs_once_and_respects_later_removals(self):
        assinantes = Group.objects.get(name="Assinantes")
        assinantes.permissions.remove(*perms("access_certhub"))
        ensure_default_groups()  # versão já é a atual: não volta a acrescentar
        self.assertFalse(assinantes.permissions.filter(codename="access_certhub").exists())

    def test_default_administrators_have_everything(self):
        admins = Group.objects.get(name="Administradores")
        codes = {f"{p.content_type.app_label}.{p.codename}" for p in admins.permissions.select_related("content_type")}
        from .permissions import all_permission_codes
        self.assertTrue(set(all_permission_codes()) <= codes)


class GroupListTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser("root", password="x")
        self.client.force_login(self.root)

    def test_list_is_a_table_with_portuguese_labels_only(self):
        r = self.client.get("/manage/groups/")
        self.assertContains(r, "<table")
        self.assertContains(r, "Acesso a módulos")
        self.assertNotContains(r, "Can view")  # nomes de permissões em inglês do Django
        self.assertNotContains(r, "Aceder ao módulo")  # o acesso mostra-se na coluna própria, não nas permissões

    def test_rows_show_modules_permissions_and_members(self):
        make_user("ana", groups=["Assinantes"])
        row = next(x for x in self.client.get("/manage/groups/").context["rows"] if x["group"].name == "Assinantes")
        self.assertEqual([m.name for m in row["modules"]], ["CertHub"])
        self.assertEqual(row["permissions"], ["Assinar ficheiros"])
        self.assertEqual(row["members"], ["ana"])

    def test_search_by_group_or_member(self):
        make_user("zeca", groups=["Auditores"])
        by_name = self.client.get("/manage/groups/?q=assin").context["rows"]
        self.assertEqual([r["group"].name for r in by_name], ["Assinantes"])
        by_member = self.client.get("/manage/groups/?q=zeca").context["rows"]
        self.assertEqual([r["group"].name for r in by_member], ["Auditores"])
        self.assertEqual(self.client.get("/manage/groups/?q=zzz").context["rows"], [])
