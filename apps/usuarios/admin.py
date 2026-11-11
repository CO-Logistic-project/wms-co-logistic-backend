from django.contrib import admin

from .models import Permiso, Rol, RolPermiso, Usuario, UsuarioRol


@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ("correo", "nombre", "apellido", "estado", "fecha_registro")
    list_filter = ("estado",)
    search_fields = ("correo", "nombre", "apellido")
    readonly_fields = (
        "id_usuario",
        "nombre",
        "apellido",
        "correo",
        "estado",
        "fecha_registro",
        "fecha_actualizacion",
    )

    def has_add_permission(self, request):
        # Users must be created through the WMS so their credential is created too.
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Rol)
class RolAdmin(admin.ModelAdmin):
    list_display = ("nombre", "estado")
    list_filter = ("estado",)
    search_fields = ("nombre",)


@admin.register(Permiso)
class PermisoAdmin(admin.ModelAdmin):
    list_display = ("nombre", "estado")
    list_filter = ("estado",)
    search_fields = ("nombre",)


@admin.register(UsuarioRol)
class UsuarioRolAdmin(admin.ModelAdmin):
    list_display = ("id_usuario", "id_rol")
    search_fields = ("id_usuario",)


@admin.register(RolPermiso)
class RolPermisoAdmin(admin.ModelAdmin):
    list_display = ("id_rol", "id_permiso")
