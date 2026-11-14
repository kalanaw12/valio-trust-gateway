"""Deploy the Valio Aimo Agent Trust Gateway (FastAPI) to Modal.

    modal serve modal_app.py     # temporary dev URL, hot reload
    modal deploy modal_app.py    # persistent URL

Secrets (VALIO_API_KEY, VALIO_BASE_URL, GEMINI_API_KEY) come from the Modal Secret "valio-secrets".
The local .env file is never uploaded.
"""
import modal

app = modal.App("valio-trust-gateway")

REMOTE = "/root"  # Modal's working directory; the app resolves data/, policies.yaml, contacts.yaml relative to it

image = (
    modal.Image.debian_slim(python_version="3.11")
    # CPU-only torch first: keeps the image ~2 GB smaller than the default CUDA build
    .pip_install("torch", index_url="https://download.pytorch.org/whl/cpu")
    .pip_install_from_requirements("requirements.txt")
    .env({
        "PYTHONUNBUFFERED": "1",
        "CACHE_DIR": f"{REMOTE}/.cache",
        "HF_HOME": f"{REMOTE}/.cache/hf",
        "DB_PATH": f"{REMOTE}/var/gateway.db",
        "AUDIT_FILE": f"{REMOTE}/var/audit_log.jsonl",
        "GATEWAY_SEMANTIC": "1",
    })
    # Application code + challenge data + config files the app needs at startup.
    # copy=True bakes them into the image so the embedding step below can use them.
    .add_local_dir("src", f"{REMOTE}/src", copy=True, ignore=["**/__pycache__/**"])
    .add_local_dir("data", f"{REMOTE}/data", copy=True)
    .add_local_file("policies.yaml", f"{REMOTE}/policies.yaml", copy=True)
    .add_local_file("contacts.yaml", f"{REMOTE}/contacts.yaml", copy=True)
    # Pre-computed catalog embeddings (17,546 products), so they are not recomputed on CPU in the build
    .add_local_dir(".cache", f"{REMOTE}/.cache", copy=True, ignore=["hf/**"])
    # Bake the embedding model + FAISS index into the image so cold starts take seconds.
    # (If this fails the gateway still works with lexical search.)
    .run_commands(
        f'cd {REMOTE} && python -c "from src.data_adapter import ProductCatalog, SemanticIndex; '
        'SemanticIndex(ProductCatalog().load()).build()" || echo "semantic index skipped"',
    )
)

env_secret = modal.Secret.from_name("valio-secrets")

# Persistent storage for var/: the SQLite database (orders, approvals, users, trusted rules),
# the hash-chained audit log and the signing key all survive redeploys and cold starts.
# Modal commits changes in the background and when the container stops.
vol = modal.Volume.from_name("valio-data", create_if_missing=True)


@app.function(
    image=image,
    secrets=[env_secret],
    volumes={f"{REMOTE}/var": vol},
    # ONE container on purpose: the live WebSocket hub, chat memory and SQLite DB are per process
    # (and a single writer keeps the SQLite file on the Volume consistent).
    max_containers=1,
    memory=2048,              # sentence-transformers + FAISS
    scaledown_window=600,     # stay warm 10 min after the last request
    timeout=3600,             # long-lived dashboard WebSocket connections
)
# `allow_concurrent_inputs=100` was removed from Modal 1.x; this is its replacement.
@modal.concurrent(max_inputs=100)
@modal.asgi_app()
def fastapi_app():
    import os
    vol.reload()                                   # read the latest committed database / audit state
    os.makedirs(f"{REMOTE}/var", exist_ok=True)
    os.chdir(REMOTE)
    from src.main import app as web_app
    return web_app
