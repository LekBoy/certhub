from django.shortcuts import redirect
from django.urls import reverse


class ForcePasswordChangeMiddleware:
    """Utilizadores com palavra-passe temporária só podem trocar a palavra-passe ou sair."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            profile = getattr(user, "profile", None)
            if profile is not None and profile.must_change_password:
                allowed = (reverse("portal:password"), reverse("portal:logout"))
                if request.path not in allowed and not request.path.startswith("/static/"):
                    return redirect("portal:password")
        return self.get_response(request)
