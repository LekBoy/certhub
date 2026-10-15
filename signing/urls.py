from django.urls import path

from . import views

app_name = "signing"
urlpatterns = [
    path("sign/", views.sign_page, name="sign"),  # montado em /certhub/
]
