from django.core.management.base import BaseCommand, CommandError

from portal import notify


class Command(BaseCommand):
    help = "Envia por e-mail o aviso de certificados perto de expirar. Agendar 1x por dia."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Só mostra o que seria avisado.")
        parser.add_argument("--force", action="store_true",
                            help="Ignora 'ativas' e reenvia mesmo o que já foi avisado.")
        parser.add_argument("--test", action="store_true", help="Envia um e-mail de teste.")

    def handle(self, *args, **opts):
        if opts["test"]:
            ok, err = notify.send_test("linha de comandos")
            if not ok:
                raise CommandError(err)
            self.stdout.write("E-mail de teste enviado.")
            return
        res = notify.run_alerts(dry_run=opts["dry_run"], force=opts["force"])
        if res["skipped"]:
            self.stdout.write(res["skipped"])
            return
        for name, days in res.get("items", []):
            self.stdout.write(f" - {name}: {notify._when(days)}")
        if opts["dry_run"]:
            self.stdout.write(f"{res['alerts']} aviso(s) pendente(s) (nada enviado).")
        elif res["error"]:
            raise CommandError(res["error"])
        else:
            self.stdout.write(f"{res['alerts']} aviso(s) enviado(s)." if res["alerts"] else "Nada para avisar.")
