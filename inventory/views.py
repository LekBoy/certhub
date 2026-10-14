import csv
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from portal.audit import audit
from portal.permissions import perm_required

from . import parsing
from .forms import MetaForm, UploadForm
from .models import ALERT_DAYS, InventoryCertificate

MAX_FILES = 50
MAX_FILE_BYTES = 5 * 1024 * 1024
VIEW = "inventory.view_inventorycertificate"
MANAGE = "inventory.manage_inventory"


def _filtered(request):
    qs = InventoryCertificate.objects.all()
    q = request.GET.get("q", "").strip()
    kind = request.GET.get("type", "")
    status = request.GET.get("status", "")
    server = request.GET.get("server", "").strip()
    now = timezone.now()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(subject__icontains=q) | Q(issuer__icontains=q) | Q(san__icontains=q)
                       | Q(server__icontains=q) | Q(owner__icontains=q) | Q(sha1__istartswith=q) | Q(sha256__istartswith=q)
                       | Q(serial_number__istartswith=q))
    if kind in InventoryCertificate.Type.values:
        qs = qs.filter(cert_type=kind)
    if server:
        qs = qs.filter(server__iexact=server)
    if status == "expired":
        qs = qs.filter(not_after__lte=now)
    elif status == "expiring":
        qs = qs.filter(not_after__gt=now, not_after__lte=now + timedelta(days=ALERT_DAYS))
    elif status == "ok":
        qs = qs.filter(not_after__gt=now + timedelta(days=ALERT_DAYS))
    return qs, {"q": q, "type": kind, "status": status, "server": server}


@perm_required(VIEW)
def inventory_list(request):
    qs, f = _filtered(request)
    allc = InventoryCertificate.objects.all()
    now = timezone.now()
    stats = {
        "total": allc.count(),
        "ok": allc.filter(not_after__gt=now + timedelta(days=ALERT_DAYS)).count(),
        "expiring": allc.filter(not_after__gt=now, not_after__lte=now + timedelta(days=ALERT_DAYS)).count(),
        "expired": allc.filter(not_after__lte=now).count(),
    }
    servers = sorted(set(allc.exclude(server="").values_list("server", flat=True)))
    keep = "&".join(f"{k}={v}" for k, v in f.items() if v)
    return render(request, "inventory/list.html", {
        "certs": qs, "stats": stats, "filters": f, "types": InventoryCertificate.Type.choices,
        "servers": servers, "keep": keep,
    })


def _csv_safe(value):
    value = "" if value is None else str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


@perm_required(VIEW)
def inventory_export(request):
    qs, _ = _filtered(request)
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="inventario-certificados.csv"'
    resp.write("﻿")  # Excel reconhece UTF-8
    w = csv.writer(resp, delimiter=";")
    w.writerow(["Nome", "Tipo", "Servidor", "Responsável", "Utilização", "Titular", "Emissor", "Série", "SHA-1",
                "SHA-256", "Válido desde", "Expira em", "Dias restantes", "Estado", "Chave", "SAN"])
    for c in qs:
        w.writerow([_csv_safe(x) for x in (
            c.name, c.get_cert_type_display(), c.server, c.owner, c.purpose, c.subject, c.issuer, c.serial_number,
            c.sha1, c.sha256, c.not_before.date().isoformat(), c.not_after.date().isoformat(), c.days_left, c.status,
            c.key_info, ", ".join(c.san_list))])
    return resp


@perm_required(MANAGE)
def inventory_upload(request):
    form = UploadForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        files = request.FILES.getlist("files")
        if not files:
            messages.error(request, "Escolha pelo menos um ficheiro.")
        elif len(files) > MAX_FILES:
            messages.error(request, f"No máximo {MAX_FILES} ficheiros por envio.")
        else:
            results = _process(request, files, form.cleaned_data)
            return render(request, "inventory/upload_result.html", {"results": results, **_summary(results)})
    return render(request, "inventory/upload.html", {"form": form})


def _summary(results):
    count = lambda s: sum(r["status"] == s for r in results)  # noqa: E731
    return {"n_added": count("added"), "n_updated": count("updated"), "n_skipped": count("skipped"),
            "n_error": count("error")}


def _process(request, files, data):
    results = []
    meta = {k: data[k] for k in ("server", "owner", "purpose", "notes") if data.get(k)}
    for f in files:
        base = {"filename": f.name, "items": []}
        if f.size > MAX_FILE_BYTES:
            results.append({**base, "status": "error", "message": "Ficheiro demasiado grande (máx. 5 MB)."})
            continue
        try:
            certs, had_key, fmt = parsing.load_certificates(f.name, f.read(), data.get("pfx_password"))
        except parsing.ParseError as exc:
            results.append({**base, "status": "error", "message": str(exc)})
            continue
        file_items = []
        for cert in certs:
            info = parsing.describe(cert)
            if info["is_ca"] and not data.get("include_ca"):
                file_items.append({"status": "skipped", "name": info["name"], "cert": None,
                                   "message": "Certificado de CA ignorado (marque «Incluir certificados de CA»)."})
                continue
            file_items.append(_save(request, info, f.name, fmt, had_key, meta))
        for item in file_items:
            results.append({"filename": f.name, **item, "had_key": had_key})
    audit(request, "inventory_uploaded", f"{len(files)} ficheiro(s)",
          "; ".join(f"{k}={v}" for k, v in _summary(results).items()))
    return results


def _save(request, info, filename, fmt, had_key, meta):
    try:
        with transaction.atomic():
            obj = InventoryCertificate.objects.filter(sha256=info["sha256"]).first()
            created = obj is None
            if created:
                obj = InventoryCertificate(**info)
            else:  # mesmo certificado: atualiza os dados lidos (mantém o nome e as notas já escritos)
                for k, v in info.items():
                    if k != "name":
                        setattr(obj, k, v)
            obj.source_filename, obj.source_format = filename[:255], fmt
            obj.had_private_key = obj.had_private_key or had_key
            obj.uploaded_by = request.user
            for k, v in meta.items():
                setattr(obj, k, v)
            obj.save()
        return {"status": "added" if created else "updated", "name": obj.name, "cert": obj, "message": ""}
    except IntegrityError:
        return {"status": "error", "name": info["name"], "cert": None, "message": "Erro ao guardar o certificado."}


@perm_required(VIEW)
def inventory_detail(request, pk):
    cert = get_object_or_404(InventoryCertificate, pk=pk)
    can_manage = request.user.has_perm(MANAGE)
    form = MetaForm(request.POST or None, instance=cert)
    if request.method == "POST":
        if not can_manage:
            return redirect("inventory:detail", pk=pk)
        if form.is_valid():
            form.save()
            audit(request, "inventory_updated", cert.name, ", ".join(sorted(form.changed_data)))
            messages.success(request, "Dados guardados.")
            return redirect("inventory:detail", pk=pk)
    return render(request, "inventory/detail.html", {"cert": cert, "form": form, "can_manage": can_manage})


@perm_required(MANAGE)
@require_POST
def inventory_delete(request, pk):
    cert = get_object_or_404(InventoryCertificate, pk=pk)
    name = cert.name
    cert.delete()
    audit(request, "inventory_deleted", name)
    messages.success(request, f"«{name}» removido do inventário.")
    return redirect("inventory:list")
