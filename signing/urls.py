from django.urls import path

from . import views

app_name = "signing"
urlpatterns = [
    path("sign/", views.sign_page, name="sign"),
    path("api/sign/", views.sign_api, name="api_sign"),
]
