# syntax=docker/dockerfile:1
# Valio Aimo Agent Gateway. Build:  docker build -t <user>/valio-agent-gateway:1.0 .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/app/.cache/hf \
    CACHE_DIR=/app/.cache \
    AUDIT_FILE=/app/var/audit_log.jsonl \
    DB_PATH=/app/var/gateway.db \
    GATEWAY_SEMANTIC=1

WORKDIR /app

# CPU-only torch keeps the image ~2 GB smaller than the default CUDA build
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install -r requirements.txt

# Application code + challenge data + policy (policies.yaml is required at startup)
COPY policies.yaml .
COPY src/ src/
COPY data/ data/

# Non-root user; writable dirs for the embedding cache and the persistent state
RUN useradd --create-home --uid 10001 gateway \
 && mkdir -p /app/.cache /app/var \
 && chown -R gateway:gateway /app/.cache /app/var
USER gateway

# Bake the embedding model + catalog embeddings into the image so startup takes seconds.
# (If the download fails the gateway still works with lexical search.)
RUN python -c "from src.data_adapter import ProductCatalog, SemanticIndex; SemanticIndex(ProductCatalog().load()).build()"

# SQLite database + hash-chained audit log live here. Mount a persistent volume on it,
# or every redeploy starts with an empty database and a new audit chain.
VOLUME ["/app/var"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# ONE worker on purpose: the live WebSocket hub and the ephemeral signing key are per process.
# --proxy-headers: the platform terminates HTTPS; the dashboard then uses wss:// automatically.
# Secrets (VALIO_API_KEY, GEMINI_API_KEY, GATEWAY_*_KEY, ...) are injected at runtime, never baked in.
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
