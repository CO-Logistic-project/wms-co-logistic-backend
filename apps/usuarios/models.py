import uuid

from django.db import models


class Usuario(models.Model):

    id_usuario = models.UUIDField(
        primary_key=True,
        db_column="id_usuario"
    )

    nombre = models.CharField(
        max_length=255,
        db_column="nombre"
    )

    apellido = models.CharField(
        max_length=255,
        db_column="apellido"
    )

    correo = models.EmailField(
        db_column="correo"
    )

    estado = models.BooleanField(
        db_column="estado"
    )

    fecha_registro = models.DateTimeField(
        db_column="fecha_registro"
    )

    fecha_actualizacion = models.DateTimeField(
        db_column="fecha_actualizacion"
    )


    class Meta:
        managed = False

        # PostgreSQL schema.tabla
        db_table = '"usuarios"."usuario"'

        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"


    def __str__(self):
        return self.correo

class Rol(models.Model):

    id_rol = models.AutoField(
        primary_key=True,
        db_column="id_rol"
    )

    nombre = models.CharField(
        max_length=255,
        db_column="nombre"
    )

    descripcion = models.TextField(
        db_column="descripcion",
        null=True,
        blank=True
    )

    estado = models.BooleanField(
        db_column="estado"
    )


    class Meta:
        managed = False
        db_table = '"usuarios"."rol"'

        verbose_name = "Rol"
        verbose_name_plural = "Roles"


    def __str__(self):
        return self.nombre

class Permiso(models.Model):

    id_permiso = models.AutoField(
        primary_key=True,
        db_column="id_permiso"
    )

    nombre = models.CharField(
        max_length=255,
        db_column="nombre"
    )

    descripcion = models.TextField(
        db_column="descripcion",
        null=True,
        blank=True
    )

    estado = models.BooleanField(
        db_column="estado"
    )


    class Meta:
        managed = False
        db_table = '"usuarios"."permiso"'

        verbose_name = "Permiso"
        verbose_name_plural = "Permisos"


    def __str__(self):
        return self.nombre

class UsuarioRol(models.Model):

    id_usuario_rol = models.AutoField(
        primary_key=True,
        db_column="id_usuario_rol"
    )

    id_usuario = models.UUIDField(
        db_column="id_usuario"
    )

    id_rol = models.IntegerField(
        db_column="id_rol"
    )


    class Meta:
        managed = False
        db_table = '"usuarios"."usuario_rol"'

        verbose_name = "Usuario Rol"
        verbose_name_plural = "Usuarios Roles"


    def __str__(self):
        return f"{self.id_usuario} - {self.id_rol}"

class RolPermiso(models.Model):

    id_rol_permiso = models.AutoField(
        primary_key=True,
        db_column="id_rol_permiso"
    )

    id_rol = models.IntegerField(
        db_column="id_rol"
    )

    id_permiso = models.IntegerField(
        db_column="id_permiso"
    )


    class Meta:
        managed = False
        db_table = '"usuarios"."rol_permiso"'

        verbose_name = "Rol Permiso"
        verbose_name_plural = "Roles Permisos"


    def __str__(self):
        return f"Rol {self.id_rol} - Permiso {self.id_permiso}"

class Credencial(models.Model):
    """Local password credential of a WMS user (one row per user)."""

    id_usuario = models.UUIDField(primary_key=True, db_column="id_usuario")
    password_hash = models.CharField(max_length=255, db_column="password_hash")
    debe_cambiar_password = models.BooleanField(
        default=False, db_column="debe_cambiar_password"
    )
    intentos_fallidos = models.IntegerField(
        default=0, db_column="intentos_fallidos"
    )
    bloqueado_hasta = models.DateTimeField(
        null=True, blank=True, db_column="bloqueado_hasta"
    )
    ultimo_acceso = models.DateTimeField(
        null=True, blank=True, db_column="ultimo_acceso"
    )
    fecha_actualizacion = models.DateTimeField(
        db_column="fecha_actualizacion"
    )

    class Meta:
        managed = False
        db_table = '"usuarios"."credencial"'
        verbose_name = "Credencial"
        verbose_name_plural = "Credenciales"

    def __str__(self):
        return str(self.id_usuario)


class Sesion(models.Model):
    """Refresh-token session. Only the SHA-256 of the token is stored."""

    id_sesion = models.UUIDField(
        primary_key=True, default=uuid.uuid4, db_column="id_sesion"
    )
    id_usuario = models.UUIDField(db_column="id_usuario")
    token_hash = models.CharField(
        max_length=64, unique=True, db_column="token_hash"
    )
    fecha_creacion = models.DateTimeField(db_column="fecha_creacion")
    fecha_expiracion = models.DateTimeField(db_column="fecha_expiracion")
    fecha_revocacion = models.DateTimeField(
        null=True, blank=True, db_column="fecha_revocacion"
    )
    reemplazada_por = models.UUIDField(
        null=True, blank=True, db_column="reemplazada_por"
    )
    ip = models.CharField(max_length=45, null=True, blank=True, db_column="ip")
    user_agent = models.CharField(
        max_length=255, null=True, blank=True, db_column="user_agent"
    )

    class Meta:
        managed = False
        db_table = '"usuarios"."sesion"'
        verbose_name = "Sesión"
        verbose_name_plural = "Sesiones"

    def __str__(self):
        return str(self.id_sesion)
