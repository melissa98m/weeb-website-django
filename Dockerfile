# Python slim image
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PIP_NO_CACHE_DIR=1

# System deps (psycopg2 build not needed when using -binary)
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential     curl     && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# Collect static later if needed
EXPOSE 8000
CMD ["/bin/sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:${BACKEND_PORT:-8000}"]
