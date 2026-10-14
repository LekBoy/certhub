from django.urls import path

from . import views

app_name = "inventory"
urlpatterns = [
    path("", views.inventory_list, name="list"),
    path("export.csv", views.inventory_export, name="export"),
    path("upload/", views.inventory_upload, name="upload"),
    path("<int:pk>/", views.inventory_detail, name="detail"),
    path("<int:pk>/delete/", views.inventory_delete, name="delete"),
]
