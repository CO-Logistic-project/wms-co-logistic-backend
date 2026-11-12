import json
import time

from django.db import connection
from django.utils import timezone

from .models import EventoAuditoria, MetricaRendimiento
from .technical import memory_usage_mb, principal_data, sanitize_payload


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _module(path):
    parts = [part for part in path.split("/") if part and part != "api"]
    return (parts[0] if parts else "sistema")[:80]


def _action(method):
    return {
        "POST": "CREAR_O_EJECUTAR",
        "PUT": "REEMPLAZAR",
        "PATCH": "ACTUALIZAR",
        "DELETE": "ELIMINAR",
    }.get(method, "CONSULTAR")


def _request_payload(request):
    if not request.body or len(request.body) > 100_000:
        return {"detalle": "Cuerpo vacío o mayor a 100 KB."}
    content_type = request.headers.get("Content-Type", "")
    if "json" not in content_type:
        return {"content_type": content_type, "tamano": len(request.body)}
    try:
        return sanitize_payload(json.loads(request.body.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError):
        return {"detalle": "Cuerpo no interpretable."}


class TechnicalObservabilityMiddleware:
    """Records API latency and critical state changes without blocking requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith("/api/") or request.path == "/api/health/":
            return self.get_response(request)
        started = time.perf_counter()
        initial_queries = len(connection.queries)
        payload = _request_payload(request) if request.method in MUTATING_METHODS else None
        response = None
        failure = ""
        try:
            response = self.get_response(request)
            return response
        except Exception as exc:
            failure = exc.__class__.__name__
            raise
        finally:
            duration = (time.perf_counter() - started) * 1000
            status_code = getattr(response, "status_code", 500)
            try:
                MetricaRendimiento.objects.create(
                    fecha=timezone.now(),
                    metodo=request.method,
                    ruta=request.path[:500],
                    estado_http=status_code,
                    duracion_ms=round(duration, 3),
                    memoria_mb=memory_usage_mb(),
                    consultas_db=max(0, len(connection.queries) - initial_queries),
                    error=failure,
                )
            except Exception:
                pass
            if request.method in MUTATING_METHODS:
                try:
                    user_id, email = principal_data(getattr(request, "user", None))
                    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
                    address = (forwarded.split(",")[0].strip() if forwarded else request.META.get("REMOTE_ADDR", ""))[:64]
                    EventoAuditoria.objects.create(
                        id_usuario=user_id,
                        usuario=email,
                        fecha=timezone.now(),
                        modulo=_module(request.path),
                        accion=_action(request.method),
                        metodo=request.method,
                        ruta=request.path[:500],
                        datos_afectados=payload or {},
                        estado_http=status_code,
                        resultado="EXITOSO" if status_code < 400 else "FALLIDO",
                        direccion_ip=address,
                    )
                except Exception:
                    pass
