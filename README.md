# WMS Co-Logistic Backend

API empresarial del WMS construida con Django REST Framework. Supabase Auth
autentica a los usuarios y esta API valida sus JWT antes de aplicar el estado,
los roles y los permisos almacenados en PostgreSQL.

## Configuración local

1. Crea y activa un entorno virtual.
2. Instala las dependencias con `pip install -r requirements.txt`.
3. Crea `.env` y completa PostgreSQL, `SUPABASE_URL` y
   `SUPABASE_SECRET_KEY`.
4. En Supabase Auth configura una llave asimétrica RS256 o ES256.
5. Inicia el servidor con `python manage.py runserver`.

El backend obtiene las llaves públicas desde el endpoint JWKS de Supabase. La
llave `SUPABASE_SECRET_KEY=sb_secret_...` se usa solo en el servidor para las
altas y actualizaciones de Supabase Auth. Nunca debe incluirse en React, Git,
capturas ni mensajes.

## Autenticación

Las solicitudes protegidas deben enviar:

```http
Authorization: Bearer <supabase_access_token>
```

`GET /api/auth/me/` valida el token, verifica que exista un perfil activo en
`usuarios.usuario` y devuelve sus roles y permisos efectivos.

El UUID de `usuarios.usuario.id_usuario` debe ser igual al UUID del usuario en
`auth.users.id` de Supabase.

## HU-002, HU-003 y HU-004

- `GET/POST /api/users/`: consulta y registro sincronizado de usuarios.
- `PATCH /api/users/<uuid>/`: actualización sincronizada del perfil y Auth.
- `PUT /api/users/<uuid>/roles/`: reemplazo controlado de roles.
- `PATCH /api/users/<uuid>/status/`: desactivación o reactivación sincronizada
  con Supabase Auth.
- `GET/POST/PATCH /api/roles/`: administración de roles y permisos.
- `GET /api/permissions/`: catálogo de permisos activos.

Cada operación comprueba su permiso en Django. Para inicializar el primer
administrador de forma idempotente:

```bash
python manage.py bootstrap_access --admin-email admin@cologistic.com
```

Una cuenta inactiva queda bloqueada en Supabase Auth y Django continúa
rechazando cualquier access token previamente emitido al comprobar
`usuarios.usuario.estado` en cada solicitud.

## EP-02: catálogos maestros

- `GET/POST /api/clients/`: consulta y registro de clientes.
- `PATCH /api/clients/<id>/`: actualización sin reemplazar el registro ni sus
  relaciones históricas.
- `GET/POST /api/products/`: consulta filtrable y registro de productos.
- `PATCH /api/products/<id>/`: actualización conservando la identidad del
  producto.
- `POST /api/products/<id>/calculate-boxes/`: cálculo de cajas a partir de
  pallets usando el factor comercial configurado.
- `GET /api/catalogs/product-options/`: clientes, categorías y unidades para
  los formularios.
- `GET/POST /api/warehouses/`: consulta y registro de almacenes.
- `GET/POST /api/zones/`: consulta y registro de zonas.
- `GET/POST /api/locations/`: consulta filtrable y registro de ubicaciones.
- `PATCH /api/locations/<id>/`: actualización o desactivación; rechaza la
  desactivación cuando existe stock activo.
- `POST /api/imports/master-data/`: importación CSV de clientes, productos,
  almacenes o ubicaciones con reporte por fila.

Los clientes validan RUC peruano de 11 dígitos y unicidad. Los productos
validan SKU único por cliente y código EAN único. Para crear las unidades de
medida iniciales y la categoría general de forma idempotente:

```bash
python manage.py bootstrap_master_catalogs
```

La estructura de ubicaciones requiere ejecutar las migraciones versionadas:

```bash
python manage.py migrate maestros
```

La importación admite CSV UTF-8 de hasta 2 MB y 5,000 filas. Las plantillas se
descargan desde la pantalla `Importaciones` para conservar los encabezados.

## EP-03, EP-04 y EP-05

EP-03 implementa la recepción desde guías, validación física, lotes,
incidencias, asignación de ubicación e impresión del pedido de ingreso. EP-04
implementa existencias filtrables, ubicabilidad, ocupación, vencimientos,
traslados internos confirmables y división/reempaque de pallets con
trazabilidad padre-hijo. EP-05 incorpora pedidos de salida multilínea,
validación y reserva de stock, confirmación de picking y cierre transaccional
del despacho con descuento automático de inventario. También incluye
cancelación con liberación de reservas, sugerencia FEFO, picking por zona,
historial y tiempos, incidencias e impresión del pedido de salida.

Para preparar las estructuras y los permisos de ambos módulos:

```bash
python manage.py migrate
python manage.py bootstrap_access --admin-email admin@cologistic.com
```

## EP-06: Reportes y BI

EP-06 incorpora un dashboard consolidado con inventario, ocupación,
recepciones, despachos, movimientos, incidencias y tiempos operativos. Incluye
ocupación por almacén y zona, actividad por responsable, historial filtrable de
movimientos, trazabilidad integral del producto y exportaciones nativas PDF y
XLSX. Los reportes se calculan sobre las operaciones de EP-03, EP-04 y EP-05;
no mantienen copias paralelas de los saldos.

Los permisos nuevos son `reportes.ver`, `reportes.exportar` y
`trazabilidad.ver`. Ejecuta nuevamente `bootstrap_access` para asignarlos a
Gerencia, Jefe de Operaciones, Analista de Inventarios y Administrador TI.

## EP-07: Planificación y capacidad operativa

EP-07 proyecta la ocupación diaria en pallets equivalentes combinando la
capacidad actual con recepciones y despachos programados. Permite consultar por
almacén, cliente y periodo, comparar el plan con la ocupación real reconstruida
y detectar fechas que superan un umbral configurable. La vista operativa
consolida capacidad disponible, volumen de entrada/salida y documentos
programados para apoyar la asignación de espacios, personal y recursos.

El permiso `planificacion.ver` habilita el módulo para Gerencia, Jefe de
Operaciones, Analista de Inventarios y Administrador TI.

## EP-08: Operaciones técnicas

EP-08 agrega una consola exclusiva para Administrador TI con monitoreo de
disponibilidad, incidentes, telemetría, auditoría exportable, integraciones,
políticas de conservación y despliegues controlados. Los respaldos manuales o
programados registran responsable, tamaño, checksum y resultado.

La restauración real está protegida por `TECHNICAL_ALLOW_RESTORE=false` de
forma predeterminada y exige confirmación exacta. Los despliegues requieren una
versión aprobada, plan de reversión y respaldo válido previo. Ejecuta nuevamente
`bootstrap_access` para asignar los permisos técnicos al rol Administrador TI.

## EP-09: Acondicionamiento de mercadería

EP-09 incorpora solicitudes facturables de repaletizado, registro de su
ejecución con paleta origen/destino, certificación y tarifa, además del
reencajado con cantidades de cajas de origen y destino. Cada servicio conserva
el cliente, stock, responsables y fechas sin alterar el saldo de inventario.

Los servicios completados generan reportes PDF o Excel y pueden marcarse como
enviados a facturación. Los permisos `acondicionamiento.ver`,
`acondicionamiento.solicitar`, `acondicionamiento.ejecutar` y
`acondicionamiento.facturacion` separan las responsabilidades del Cliente,
Operario de almacén y responsables administrativos.

## Pruebas automatizadas

```bash
python manage.py test
```

## Backend en Docker

El entorno virtual local revisado usa Python 3.12.9; la imagen usa la rama
Python 3.12 sobre Debian Bookworm (el parche se actualiza con la imagen base).
Gunicorn 26.0.0 está fijado en `requirements.txt` y carga `config.wsgi:application`.
La [política oficial de soporte](https://github.com/benoitc/gunicorn/security/policy)
marca 26.0.0 como soportado y 23.0.0 como no soportado. Se eligió la versión
26.0.0 por figurar explícitamente como soportada; su
[publicación estable](https://pypi.org/project/gunicorn/26.0.0/)
declara compatibilidad con Python 3.12.
Se ejecuta con UID/GID 10001, dos workers, puerto interno 8000 y logs en
stdout/stderr. El arranque no restaura datos ni ejecuta migraciones.
El `CMD` de la imagen ya incluye `--no-control-socket`: desactiva la interfaz
de control opcional y evita que intente crear su socket bajo `/home/wms`,
ya que el usuario no tiene directorio home. No requiere variables adicionales.
Véase la [configuración oficial del socket de control](https://gunicorn.org/reference/settings/#control-socket-disable).
Supabase Auth y la validación JWT RS256/ES256 permanecen vigentes; la
autenticación local queda para otra tarea.

### Configuración al arrancar

No se copia ningún `.env` a la imagen. Solo se copian dependencias,
`manage.py`, `config/` y `apps/`; `.dockerignore` excluye también secretos,
entornos, cachés, logs y respaldos del contexto de construcción.
Entrega las variables mediante `docker run --env-file <archivo-externo>` o
el gestor de secretos del entorno, nunca mediante argumentos de build.
El archivo externo debe ser privado y no versionarse.

Variables leídas por `config/settings.py`:

| Grupo | Variables |
| --- | --- |
| Django | `SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS` (separados por comas) |
| PostgreSQL | `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_SSLMODE` |
| Supabase | `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `SUPABASE_JWT_ISSUER`, `SUPABASE_JWT_AUDIENCE` |
| Frontend/CORS | `FRONTEND_URL` |
| Operaciones | `TECHNICAL_BACKUP_DIR`, `TECHNICAL_ALLOW_RESTORE`, `TECHNICAL_COMMAND_TIMEOUT`, `TECHNICAL_SLOW_REQUEST_MS` |

Para un entorno real define una `SECRET_KEY` aleatoria, `DEBUG=False`, hosts
explícitos y credenciales de una base autorizada. `DB_SSLMODE` vale `require`
por defecto. Dentro del contenedor, `localhost` se refiere al propio
contenedor: para PostgreSQL en Windows usa `host.docker.internal`; para otro
contenedor usa su nombre DNS en una red Docker compartida. No hace falta
publicar el puerto de PostgreSQL para conectar contenedores en esa red.
El issuer predeterminado es `<SUPABASE_URL>/auth/v1`, la audiencia es
`authenticated` y `TECHNICAL_ALLOW_RESTORE` debe permanecer en `false`.

### Repetir la prueba sin secretos ni base real (PowerShell)

Ejecutar desde la raíz del backend. Docker elige un puerto libre y lo publica
solo en loopback. Todos los valores siguientes son ficticios. La prueba
espera un 401 con `WWW-Authenticate: Bearer` en una ruta protegida existente.
Ese resultado comprueba Django/DRF y la protección sin consultar Supabase;
no valida una lectura de negocio ni la conexión PostgreSQL. El middleware
intenta registrar telemetría en la base y tolera que no esté disponible.

```powershell
docker build -t wms-backend:docker-test .
if ($LASTEXITCODE -ne 0) { throw 'Falló la construcción' }
$containerName = 'wms-backend-smoke-' + [guid]::NewGuid().ToString('N')
try {
    docker run -d --name $containerName -p 127.0.0.1::8000 `
      -e SECRET_KEY=smoke-only-not-for-production -e DEBUG=False `
      -e ALLOWED_HOSTS=localhost,127.0.0.1 `
      -e DB_NAME=wms_smoke -e DB_USER=wms_smoke -e DB_PASSWORD=smoke-only `
      -e DB_HOST=127.0.0.1 -e DB_PORT=1 -e DB_SSLMODE=disable `
      -e SUPABASE_URL=https://smoke.invalid -e SUPABASE_SECRET_KEY=smoke-only `
      -e TECHNICAL_ALLOW_RESTORE=False wms-backend:docker-test
    if ($LASTEXITCODE -ne 0) { throw 'Falló el arranque' }
    $binding = docker port $containerName 8000/tcp
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $status = curl.exe -s --max-time 3 -o NUL -w '%{http_code}' "http://$binding/api/auth/me/"
        if ($status -eq '401') { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "La API no respondió 401: $status" }
    $response = curl.exe -s -i --max-time 5 "http://$binding/api/auth/me/"
    if ($LASTEXITCODE -ne 0 -or ($response -join "`n") -notmatch '(?im)^WWW-Authenticate: Bearer\s*$') {
        throw 'Falta WWW-Authenticate: Bearer'
    }
    $response
    docker exec $containerName id
    docker exec $containerName gunicorn --version
    docker exec $containerName python manage.py check
    docker logs $containerName
} finally {
    # Solo elimina el contenedor de esta prueba; conserva la imagen.
    docker rm -f $containerName
}
```

Con una base de pruebas y un usuario Supabase autorizado, arranca la misma
imagen con `--env-file <archivo-externo-de-pruebas>` y las variables reales de
ese entorno. Comprueba `GET /api/auth/me/` y una lectura permitida como
`GET /api/clients/` usando el access token en `Authorization: Bearer ...`;
espera 200 y verifica el contenido. No incluyas el token en archivos del repo
ni en registros compartidos.

### Migraciones, restauración y respaldos

Ejecuta las migraciones como operación independiente, contra la base de
pruebas elegida, antes de la prueba de lectura:

```powershell
docker run --rm --env-file <archivo-externo-de-pruebas> wms-backend:docker-test python manage.py migrate --plan
docker run --rm --env-file <archivo-externo-de-pruebas> wms-backend:docker-test python manage.py migrate
```

Una restauración requiere otra operación explícita y una ventana de
mantenimiento; nunca va en el Dockerfile ni en el comando de inicio.
La imagen mínima no instala `pg_dump` ni `pg_restore`. EP-08 usa como
alternativa `dumpdata` comprimido, que no equivale a un respaldo completo de
PostgreSQL y no sirve para su restauración controlada de formato custom.
Antes de habilitar esos flujos, identifica la versión del servidor destino
con `SHOW server_version;` e incorpora un cliente PostgreSQL de la misma
versión mayor (por ejemplo, servidor 17: cliente 17, con parche actualizado).
Usa también ese cliente para generar y validar el dump; no asumas que el
cliente predeterminado de Debian coincide con Supabase. Verifica
`pg_dump --version` y `pg_restore --version`. La versión del destino no se
ha comprobado en esta prueba. Para operaciones EP-08 persistentes, monta
`/app/var/backups` con permisos de escritura para UID/GID 10001 y conserva
`TECHNICAL_ALLOW_RESTORE=false` salvo la ventana explícita de restauración.

### Archivos estáticos

Actualmente solo existe `STATIC_URL=static/`: no hay `STATIC_ROOT`, WhiteNoise
ni servidor de estáticos. Gunicorn no sirve los CSS/JS de `/admin/`.
La prueba JSON no requiere estáticos. Antes de publicar el admin, configura
un servidor externo (por ejemplo Nginx) para `/static/` y recoge los archivos
en un volumen independiente. Sin modificar los settings actuales se puede
generar la salida así, usando un volumen preparado para UID 10001:

```powershell
docker run --rm --env-file <archivo-externo-de-pruebas> --mount type=volume,source=wms-static,target=/app/staticfiles wms-backend:docker-test python -c "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings'); import django; django.setup(); from django.conf import settings; settings.STATIC_ROOT='/app/staticfiles'; from django.core.management import call_command; call_command('collectstatic', interactive=False)"
```

El servidor de estáticos debe montar ese volumen de solo lectura. Este paso
es independiente del arranque, de las migraciones y de la restauración.

### Resultado de la prueba del 9 de noviembre de 2026

- Construcción de `wms-backend:docker-test` completada con Python 3.12.16
  y Gunicorn 26.0.0; versión verificada con `gunicorn --version` dentro del
  contenedor y ambos workers cargaron Django.
- Publicación temporal en `127.0.0.1:65018`; `GET /api/auth/me/` sin token
  devolvió 401 JSON y `WWW-Authenticate: Bearer`, como corresponde.
- `python manage.py check` sin incidencias; proceso con UID/GID 10001.
- Imagen reconstruida con `--no-control-socket` en su `CMD`. Prueba repetida
  sin `GUNICORN_CMD_ARGS` (ausencia verificada dentro del contenedor): los logs
  no muestran errores del socket de control ni permisos denegados.
- La prueba inicial de Docker comprobó la ausencia de `.env*` y `.git` en
  `/app`. En esta actualización no se leyó el `.env` real y solo se
  inyectaron valores ficticios al contenedor.
- Contenedor temporal eliminado; imagen conservada para revisión.
- Pendientes: lectura autenticada de la API contra PostgreSQL de pruebas y
  validación real de Supabase (no se proporcionó una base/token de pruebas),
  migraciones/restauración, versión del cliente PostgreSQL del destino y
  publicación de estáticos. No se ejecutó commit, push ni despliegue.
