"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.db import connection
from django.http import JsonResponse
from django.urls import include, path


def health_check(request):
    """Lightweight liveness probe (passes ?deep=1 to also check DB connectivity)."""
    payload = {"status": "ok", "service": "wms-api"}
    if request.GET.get("deep") == "1":
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            payload["database"] = "ok"
        except Exception as exc:
            return JsonResponse(
                {"status": "error", "service": "wms-api", "database": str(exc)},
                status=503,
            )
    return JsonResponse(payload)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/health/', health_check, name='api-health'),
    path('api/', include('apps.usuarios.urls')),
    path('api/', include('apps.maestros.urls')),
    path('api/', include('apps.recepciones.urls')),
    path('api/', include('apps.inventario.urls')),
    path('api/', include('apps.pedidos.urls')),
    path('api/', include('apps.reportes.urls')),
    path('api/', include('apps.servicios.urls')),
]
