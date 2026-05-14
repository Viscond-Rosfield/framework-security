# syntax=docker/dockerfile:1.7

# ThreatLens - Container image
# Build:  docker build -t threatlens .
# Run:    docker run -p 8000:8000 --env-file .env threatlens

FROM python:3.11-slim

# Boas praticas: nao rodar como root, layer cache otimizado
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencias do sistema (mantenha o minimo)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        libyara9 \
    && rm -rf /var/lib/apt/lists/*

# Cria usuario sem privilegios
RUN useradd --create-home --shell /bin/bash threatlens

# Instala dependencias Python primeiro (melhor cache)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia o codigo
COPY --chown=threatlens:threatlens . .

# Diretorios usados em runtime devem pertencer ao user
RUN mkdir -p data uploads && chown -R threatlens:threatlens data uploads

USER threatlens

EXPOSE 8000

# Healthcheck consulta /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
