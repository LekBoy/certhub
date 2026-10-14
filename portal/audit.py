from .models import AuditEvent


def audit(request, action: str, target: str = "", detail: str = ""):
    user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
    AuditEvent.objects.create(
        user=user, username=user.username if user else "", action=action, target=target[:255], detail=detail,
        ip_address=request.META.get("REMOTE_ADDR") or None,
    )
