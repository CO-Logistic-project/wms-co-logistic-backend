FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 wms \
    && useradd --uid 10001 --gid wms --no-create-home --shell /usr/sbin/nologin wms \
    && mkdir -p /app/var/backups /app/staticfiles \
    && chown -R wms:wms /app/var /app/staticfiles

COPY manage.py ./
COPY config/ ./config/
COPY apps/ ./apps/

USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--no-control-socket", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-"]
