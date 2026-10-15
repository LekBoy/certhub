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
from .forms import MetaForm, UploadForm, UsageForm
from .models import ALERT_DAYS, CertificateUsage, InventoryCertificate

MAX_FILES = 50
MAX_FILE_BYTES = 5 * 1024 * 1024
VIEW = "inventory.view_inventorycertificate"
MANAGE = "inventory.manage_inventory"


def _filtered(request):
    qs = InventoryCertificate.objects.prefetch_related("usages")
    q = request.GET.get("q", "").strip()
    kind = request.GET.get("type", "")
    status = request.GET.get("status", "")
    server = request.GET.get("server", "").strip()
    app = request.GET.get("app", "").strip()
    now = timezone.now()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(subject__icontains=q) | Q(issuer__icontains=q) | Q(san__icontains=q)
                       | Q(owner__icontains=q) | Q(sha1__istartswith=q) | Q(sha256__istartswith=q)
                       | Q(serial_number__istartswith=q) | Q(usages__hostname__icontains=q)
                       | Q(usages__ip_address__startswith=q) | Q(usages__application__icontains=q)).distinct()
    if kind in InventoryCertificate.Type.values:
        qs = qs.filter(cert_type=kind)
    if server:
        qs = qs.filter(usages__hostname__iexact=server).distinct()
    if app:
        qs = qs.filter(usages__application__iexact=app).distinct()
    if status == "expired":
        qs = qs.filter(not_after__lte=now)
    elif status == "expiring":
        qs = qs.filter(not_after__gt=now, not_after__lte=now + timedelta(days=ALERT_DAYS))
    elif status == "ok":
        qs = qs.filter(not_after__gt=now + timedelta(days=ALERT_DAYS))
    return qs, {"q": q, "type": kind, "status": status, "server": server, "app": app}


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
    usages = CertificateUsage.objects
    servers = sorted(set(usages.exclude(hostname="").values_list("hostname", flat=True)))
    apps = sorted(set(usages.exclude(application="").values_list("application", flat=True)))
    keep = "&".join(f"{k}={v}" for k, v in f.items() if v)
    return render(request, "inventory/list.html", {
        "certs": qs, "stats": stats, "filters": f, "types": InventoryCertificate.Type.choices,
        "servers": servers, "apps": apps, "keep": keep,
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
    w.writerow(["Nome", "Tipo", "Servidores", "IPs", "Aplicações", "Responsável", "Titular", "Emissor", "Série",
                "SHA-1", "SHA-256", "Válido desde", "Expira em", "Dias restantes", "Estado", "Chave", "SAN"])
    for c in qs:
        us = list(c.usages.all())
        join = lambda values: "; ".join(dict.fromkeys(v for v in values if v))  # noqa: E731
        w.writerow([_csv_safe(x) for x in (
            c.name, c.get_cert_type_display(), join(u.hostname for u in us), join(u.endpoint for u in us),
            join(u.application for u in us), c.owner, c.subject, c.issuer, c.serial_number, c.sha1, c.sha256,
            c.not_before.date().isoformat(), c.not_after.date().isoformat(), c.days_left, c.status, c.key_info,
            ", ".join(c.san_list))])
    return resp


USAGE_KEYS = ("hostname", "ip_address", "port", "application", "environment")


def _read_usage_rows(post):
    """Lê as linhas «Onde é usado» (campos repetidos u_hostname, u_ip_address, ...). Ignora as vazias."""
    cols = {k: post.getlist(f"u_{k}") for k in USAGE_KEYS}
    rows = []
    for i in range(max(len(v) for v in cols.values())):
        row = {k: (cols[k][i].strip() if i < len(cols[k]) else "") for k in USAGE_KEYS}
        if any(row.values()):
            rows.append(row)
    return rows


@perm_required(MANAGE)
def inventory_upload(request):
    form = UploadForm(request.POST if request.method == "POST" else None)
    rows = [{k: "" for k in USAGE_KEYS}]
    if request.method == "POST":
        rows, usages, rows_ok = _read_usage_rows(request.POST), [], True
        for row in rows:
            uf = UsageForm(row)
            if uf.is_valid():
                usages.append({k: v for k, v in uf.cleaned_data.items() if v not in (None, "")})
            else:
                rows_ok = False
                row["errors"] = [e for errs in uf.errors.values() for e in errs]
        files = request.FILES.getlist("files")
        if form.is_valid() and rows_ok:
            if not files:
                messages.error(request, "Escolha pelo menos um ficheiro.")
            elif len(files) > MAX_FILES:
                messages.error(request, f"No máximo {MAX_FILES} ficheiros por envio.")
            else:
                results = _process(request, files, form.cleaned_data, usages)
                return render(request, "inventory/upload_result.html", {"results": results, **_summary(results)})
        rows = rows or [{k: "" for k in USAGE_KEYS}]
    return render(request, "inventory/upload.html", {
        "form": form, "rows": rows, "environments": CertificateUsage.Environment.choices,
    })


def _summary(results):
    count = lambda s: sum(r["status"] == s for r in results)  # noqa: E731
    return {"n_added": count("added"), "n_updated": count("updated"), "n_skipped": count("skipped"),
            "n_error": count("error")}


def _process(request, files, data, usages):
    results = []
    meta = {k: data[k] for k in ("owner", "notes") if data.get(k)}
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
        infos = [parsing.describe(c) for c in certs]
        only_ca = all(i["is_ca"] for i in infos)  # ficheiro só com CAs: foi carregado de propósito, entra sempre
        for info in infos:
            if info["is_ca"] and not data.get("include_ca") and not only_ca:
                file_items.append({"status": "skipped", "name": info["name"], "cert": None,
                                   "message": "Certificado de CA ignorado (marque «Incluir certificados de CA»)."})
                continue
            item = _save(request, info, f.name, fmt, had_key, meta, usages)
            if only_ca and not data.get("include_ca") and item["status"] in ("added", "updated"):
                item["message"] = "Importado como CA (o ficheiro só tinha certificados de CA). "
            file_items.append(item)
        for item in file_items:
            results.append({"filename": f.name, **item, "had_key": had_key})
    audit(request, "inventory_uploaded", f"{len(files)} ficheiro(s)",
          "; ".join(f"{k}={v}" for k, v in _summary(results).items()))
    return results


def _save(request, info, filename, fmt, had_key, meta, usages):
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
            for usage in usages:
                if not obj.usages.filter(**usage).exists():
                    CertificateUsage.objects.create(certificate=obj, **usage)
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
    return render(request, "inventory/detail.html", {
        "cert": cert, "form": form, "can_manage": can_manage, "usage_form": UsageForm(),
        "usages": cert.usages.all(),
    })


@perm_required(MANAGE)
@require_POST
def usage_add(request, pk):
    cert = get_object_or_404(InventoryCertificate, pk=pk)
    form = UsageForm(request.POST)
    if form.is_valid():
        usage = form.save(commit=False)
        usage.certificate = cert
        usage.save()
        audit(request, "inventory_usage_added", cert.name, usage.where)
        messages.success(request, "Utilização adicionada.")
        return redirect("inventory:detail", pk=pk)
    return render(request, "inventory/detail.html", {
        "cert": cert, "form": MetaForm(instance=cert), "can_manage": True, "usage_form": form,
        "usages": cert.usages.all(), "usage_error": True,
    })


@perm_required(MANAGE)
def usage_edit(request, pk):
    usage = get_object_or_404(CertificateUsage.objects.select_related("certificate"), pk=pk)
    form = UsageForm(request.POST or None, instance=usage)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit(request, "inventory_usage_updated", usage.certificate.name, usage.where)
        messages.success(request, "Utilização atualizada.")
        return redirect("inventory:detail", pk=usage.certificate_id)
    return render(request, "inventory/usage_form.html", {"form": form, "usage": usage, "cert": usage.certificate})


@perm_required(MANAGE)
@require_POST
def usage_delete(request, pk):
    usage = get_object_or_404(CertificateUsage.objects.select_related("certificate"), pk=pk)
    cert_pk, name, where = usage.certificate_id, usage.certificate.name, usage.where
    usage.delete()
    audit(request, "inventory_usage_removed", name, where)
    messages.success(request, "Utilização removida.")
    return redirect("inventory:detail", pk=cert_pk)


@perm_required(MANAGE)
@require_POST
def inventory_delete(request, pk):
    cert = get_object_or_404(InventoryCertificate, pk=pk)
    name = cert.name
    cert.delete()
    audit(request, "inventory_deleted", name)
    messages.success(request, f"«{name}» removido do inventário.")
    return redirect("inventory:list")
