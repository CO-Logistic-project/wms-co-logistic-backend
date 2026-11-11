import csv
import gzip
import hashlib
import io
import json
import os
import resource
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.db import connection
from django.db.models import Avg, Count, Max, Q
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import (
    Despliegue,
    EjecucionIntegracion,
    EventoAuditoria,
    IncidenteSistema,
    MetricaRendimiento,
    PoliticaConservacion,
    ProgramacionRespaldo,
    RespaldoBaseDatos,
    RestauracionBaseDatos,
    VersionDespliegue,
)


SENSITIVE_KEYS = {"password", "contrasena", "contraseña", "token", "secret", "authorization", "apikey", "api_key"}


def principal_data(principal):
    profile = getattr(principal, "profile", principal)
    identifier = getattr(principal, "id", None) or getattr(profile, "id_usuario", None)
    email = getattr(principal, "email", "") or getattr(profile, "correo", "")
    return identifier, email


def sanitize_payload(value):
    if isinstance(value, dict):
        return {
            key: "[PROTEGIDO]" if key.lower() in SENSITIVE_KEYS else sanitize_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value[:100]]
    if isinstance(value, str) and len(value) > 500:
        return f"{value[:500]}…"
    return value


def _backup_directory():
    directory = Path(
        getattr(settings, "TECHNICAL_BACKUP_DIR", settings.BASE_DIR / "var" / "backups")
    ).resolve()
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    return directory


def _database_environment():
    config = settings.DATABASES["default"]
    command_env = os.environ.copy()
    if config.get("PASSWORD"):
        command_env["PGPASSWORD"] = str(config["PASSWORD"])
    if config.get("OPTIONS", {}).get("sslmode"):
        command_env["PGSSLMODE"] = str(config["OPTIONS"]["sslmode"])
    return config, command_env


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pg_arguments(binary, output_path=None):
    config, command_env = _database_environment()
    args = [binary]
    if config.get("HOST"):
        args.extend(["--host", str(config["HOST"])])
    if config.get("PORT"):
        args.extend(["--port", str(config["PORT"])])
    if config.get("USER"):
        args.extend(["--username", str(config["USER"])])
    if config.get("NAME"):
        args.extend(["--dbname", str(config["NAME"])])
    if output_path:
        args.extend(["--file", str(output_path)])
    return args, command_env


def _portable_backup(path):
    with gzip.open(path, "wt", encoding="utf-8") as target:
        call_command(
            "dumpdata",
            "--natural-foreign",
            "--natural-primary",
            "--exclude=admin.logentry",
            "--exclude=sessions.session",
            "--exclude=contenttypes",
            stdout=target,
        )


def create_backup(principal=None, backup_type="MANUAL"):
    user_id, email = principal_data(principal)
    record = RespaldoBaseDatos.objects.create(
        tipo=backup_type,
        estado="EJECUTANDO",
        fecha_inicio=timezone.now(),
        id_usuario=user_id,
        usuario=email,
        motor="PostgreSQL",
    )
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M%S")
    directory = _backup_directory()
    pg_dump = shutil.which("pg_dump")
    suffix = ".dump" if pg_dump else ".json.gz"
    path = directory / f"wms-{record.id_respaldo}-{stamp}{suffix}"
    try:
        if pg_dump:
            args, command_env = _pg_arguments(pg_dump, path)
            args.extend(["--format=custom", "--no-owner", "--no-acl"])
            completed = subprocess.run(
                args,
                env=command_env,
                capture_output=True,
                text=True,
                timeout=getattr(settings, "TECHNICAL_COMMAND_TIMEOUT", 900),
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "pg_dump no pudo generar el respaldo.")
            engine = "PostgreSQL custom"
        else:
            _portable_backup(path)
            engine = "Django JSON gzip"
        if not path.exists() or path.stat().st_size == 0:
            raise RuntimeError("El respaldo generado está vacío.")
        record.estado = "VALIDO"
        record.valido = True
        record.archivo = str(path)
        record.tamano_bytes = path.stat().st_size
        record.checksum_sha256 = _sha256(path)
        record.motor = engine
        record.resultado = "Respaldo generado y validado correctamente."
    except Exception as exc:
        if path.exists():
            path.unlink(missing_ok=True)
        record.estado = "FALLIDO"
        record.valido = False
        record.resultado = str(exc)[:4000]
    record.fecha_fin = timezone.now()
    record.save()
    return record


def validate_backup(record):
    path = Path(record.archivo) if record.archivo else None
    valid = bool(path and path.exists() and path.is_file() and path.stat().st_size > 0)
    result = "El archivo no existe o está vacío."
    if valid and _sha256(path) != record.checksum_sha256:
        valid = False
        result = "El checksum no coincide; el respaldo puede estar alterado."
    elif valid and record.motor == "PostgreSQL custom":
        pg_restore = shutil.which("pg_restore")
        if not pg_restore:
            valid = False
            result = "pg_restore no está disponible para validar el archivo."
        else:
            completed = subprocess.run(
                [pg_restore, "--list", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            valid = completed.returncode == 0
            result = "Respaldo PostgreSQL íntegro." if valid else (completed.stderr.strip() or "Formato inválido.")
    elif valid:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as source:
                first = source.read(1)
            valid = first == "["
            result = "Respaldo lógico íntegro." if valid else "El contenido lógico no es válido."
        except (OSError, UnicodeError):
            valid = False
            result = "El archivo comprimido no es válido."
    record.valido = valid
    record.estado = "VALIDO" if valid else "INVALIDO"
    record.resultado = result[:4000]
    record.fecha_fin = timezone.now()
    record.save(update_fields=["valido", "estado", "resultado", "fecha_fin"])
    return record


def restore_backup(record, principal, confirmation):
    expected = f"RESTAURAR {record.id_respaldo}"
    if confirmation != expected:
        raise ValidationError({"confirmacion": [f'Escribe exactamente "{expected}".']})
    validate_backup(record)
    if not record.valido:
        raise ValidationError({"respaldo": [record.resultado]})
    if not getattr(settings, "TECHNICAL_ALLOW_RESTORE", False):
        raise ValidationError({
            "restauracion": [
                "La restauración está protegida. Activa TECHNICAL_ALLOW_RESTORE=true en una ventana de mantenimiento."
            ]
        })
    if record.motor != "PostgreSQL custom":
        raise ValidationError({"respaldo": ["La restauración controlada requiere un respaldo PostgreSQL custom."]})

    user_id, email = principal_data(principal)
    restoration = RestauracionBaseDatos.objects.create(
        id_respaldo=record.id_respaldo,
        estado="EJECUTANDO",
        fecha_inicio=timezone.now(),
        id_usuario=user_id,
        usuario=email,
    )
    try:
        pg_restore = shutil.which("pg_restore")
        if not pg_restore:
            raise RuntimeError("pg_restore no está disponible.")
        args, command_env = _pg_arguments(pg_restore)
        args.extend(["--clean", "--if-exists", "--no-owner", "--no-acl", record.archivo])
        connection.close()
        completed = subprocess.run(
            args,
            env=command_env,
            capture_output=True,
            text=True,
            timeout=getattr(settings, "TECHNICAL_COMMAND_TIMEOUT", 900),
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "La restauración falló.")
        restoration.estado = "COMPLETADA"
        restoration.resultado = "Base de datos restaurada y conexión reiniciada."
        record.estado = "RESTAURADO"
        record.save(update_fields=["estado"])
    except Exception as exc:
        restoration.estado = "FALLIDA"
        restoration.resultado = str(exc)[:4000]
    restoration.fecha_fin = timezone.now()
    restoration.save()
    return restoration


def get_schedule():
    schedule = ProgramacionRespaldo.objects.order_by("id_programacion").first()
    if schedule:
        return schedule
    return ProgramacionRespaldo.objects.create(
        activa=False,
        frecuencia_horas=24,
        retencion_dias=30,
        fecha_actualizacion=timezone.now(),
    )


def run_scheduled_backup():
    schedule = get_schedule()
    now = timezone.now()
    if not schedule.activa or (schedule.proxima_ejecucion and schedule.proxima_ejecucion > now):
        return None
    backup = create_backup(None, "PROGRAMADO")
    schedule.ultima_ejecucion = now
    schedule.proxima_ejecucion = now + timedelta(hours=schedule.frecuencia_horas)
    schedule.fecha_actualizacion = now
    schedule.save()
    cutoff = now - timedelta(days=schedule.retencion_dias)
    for expired in RespaldoBaseDatos.objects.filter(fecha_inicio__lt=cutoff, tipo="PROGRAMADO"):
        if expired.archivo:
            Path(expired.archivo).unlink(missing_ok=True)
        expired.estado = "EXPIRADO"
        expired.valido = False
        expired.resultado = "Eliminado por la política de retención de respaldos."
        expired.save(update_fields=["estado", "valido", "resultado"])
    return backup


def _record_component_state(component, healthy, detail):
    open_incident = IncidenteSistema.objects.filter(
        componente=component, estado="ABIERTO", fecha_fin__isnull=True
    ).order_by("-fecha_inicio").first()
    if healthy and open_incident:
        open_incident.estado = "RESUELTO"
        open_incident.fecha_fin = timezone.now()
        open_incident.detalle = detail
        open_incident.save(update_fields=["estado", "fecha_fin", "detalle"])
    elif not healthy and not open_incident:
        IncidenteSistema.objects.create(
            componente=component,
            estado="ABIERTO",
            fecha_inicio=timezone.now(),
            detalle=detail[:4000],
        )


def system_health(record_incidents=True):
    checks = []
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        checks.append({"componente": "Base de datos", "estado": "OPERATIVO", "detalle": "Conexión disponible."})
    except Exception as exc:
        checks.append({"componente": "Base de datos", "estado": "FALLA", "detalle": str(exc)[:500]})

    signing_key = getattr(settings, "JWT_SIGNING_KEY", "")
    auth_ok = bool(signing_key) and not signing_key.startswith("dev-only-")
    checks.append({
        "componente": "Autenticación local",
        "estado": "OPERATIVO" if auth_ok else "DEGRADADO",
        "detalle": "Llave de firma JWT configurada." if auth_ok else "Falta JWT_SIGNING_KEY o se usa la llave de desarrollo.",
    })
    try:
        directory = _backup_directory()
        writable = os.access(directory, os.W_OK)
    except OSError:
        writable = False
        directory = Path("-")
    checks.append({
        "componente": "Almacenamiento de respaldos",
        "estado": "OPERATIVO" if writable else "FALLA",
        "detalle": f"Directorio: {directory}",
    })
    checks.append({"componente": "API WMS", "estado": "OPERATIVO", "detalle": "El servicio respondió al diagnóstico."})
    if record_incidents:
        for item in checks:
            _record_component_state(item["componente"], item["estado"] == "OPERATIVO", item["detalle"])
    available = sum(1 for item in checks if item["estado"] == "OPERATIVO")
    return {
        "estado": "OPERATIVO" if available == len(checks) else "DEGRADADO",
        "disponibilidad": round(available / len(checks) * 100, 2),
        "servicios_activos": available,
        "servicios_total": len(checks),
        "componentes": checks,
        "consultado_en": timezone.now(),
    }


def performance_summary(days=7):
    since = timezone.now() - timedelta(days=days)
    query = MetricaRendimiento.objects.filter(fecha__gte=since)
    summary = query.aggregate(
        solicitudes=Count("id_metrica"),
        promedio_ms=Avg("duracion_ms"),
        maximo_ms=Max("duracion_ms"),
        errores=Count("id_metrica", filter=Q(estado_http__gte=500)),
    )
    slow_limit = getattr(settings, "TECHNICAL_SLOW_REQUEST_MS", 1000)
    return {
        "periodo_dias": days,
        "limite_ms": slow_limit,
        "solicitudes": summary["solicitudes"] or 0,
        "promedio_ms": round(float(summary["promedio_ms"] or 0), 2),
        "maximo_ms": round(float(summary["maximo_ms"] or 0), 2),
        "errores": summary["errores"] or 0,
        "operaciones_lentas": [serialize_performance(item) for item in query.filter(duracion_ms__gte=slow_limit).order_by("-fecha")[:25]],
        "recientes": [serialize_performance(item) for item in query.order_by("-fecha")[:50]],
    }


def serialize_performance(item):
    return {
        "id_metrica": item.id_metrica,
        "fecha": item.fecha,
        "metodo": item.metodo,
        "ruta": item.ruta,
        "estado_http": item.estado_http,
        "duracion_ms": float(item.duracion_ms),
        "memoria_mb": float(item.memoria_mb) if item.memoria_mb is not None else None,
        "consultas_db": item.consultas_db,
        "error": item.error,
    }


def serialize_backup(item):
    return {
        "id_respaldo": item.id_respaldo,
        "tipo": item.tipo,
        "estado": item.estado,
        "fecha_inicio": item.fecha_inicio,
        "fecha_fin": item.fecha_fin,
        "usuario": item.usuario,
        "archivo": Path(item.archivo).name if item.archivo else "",
        "tamano_bytes": item.tamano_bytes,
        "checksum_sha256": item.checksum_sha256,
        "motor": item.motor,
        "valido": item.valido,
        "resultado": item.resultado,
    }


def serialize_audit(item):
    return {
        "id_evento": item.id_evento,
        "usuario": item.usuario,
        "fecha": item.fecha,
        "modulo": item.modulo,
        "accion": item.accion,
        "metodo": item.metodo,
        "ruta": item.ruta,
        "datos_afectados": item.datos_afectados,
        "estado_http": item.estado_http,
        "resultado": item.resultado,
        "direccion_ip": item.direccion_ip,
    }


def audit_csv(queryset):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Fecha", "Usuario", "Módulo", "Acción", "Método", "Ruta", "Estado", "Resultado", "Datos afectados"])
    for item in queryset.iterator():
        writer.writerow([
            item.fecha.isoformat(), item.usuario, item.modulo, item.accion,
            item.metodo, item.ruta, item.estado_http, item.resultado,
            json.dumps(item.datos_afectados, ensure_ascii=False),
        ])
    return output.getvalue().encode("utf-8-sig")


def memory_usage_mb():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return value / 1024 / 1024
    return value / 1024
