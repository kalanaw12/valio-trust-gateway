# Deploying the Valio Aimo Agent Gateway

The gateway is a single CPU container: FastAPI app, SQLite database and audit log, listening on port **8000**.
It needs **no GPU**, **one replica** and **one persistent volume** mounted at `/app/var`.

> ⚠️ **Keep the image private.** It bundles the challenge dataset (`data/`), which may only be used for
> Junction 2026. Use a **private** Docker Hub repository (the free plan includes one) or Verda's private
> registry. Never push it to a public repository.

---

## 1. Build and test locally

Docker Desktop is required ([docker.com](https://www.docker.com/products/docker-desktop/)).

```powershell
cd "d:\program j"
docker build -t valio-agent-gateway:1.0 .
```

The first build takes a while: CPU-only PyTorch plus a one-time embedding of 17.5k products, cached in the image.
`.env` is excluded by `.dockerignore`, so no secrets end up in the image.

Smoke test, using your local `.env` for the keys:

```powershell
docker volume create gateway-data
docker run --rm -p 8000:8000 --env-file .env -v gateway-data:/app/var valio-agent-gateway:1.0
# open http://localhost:8000/health  then  http://localhost:8000/dashboard
```

## 2. Push to a private Docker Hub repository

1. On [hub.docker.com](https://hub.docker.com), create a repository `valio-agent-gateway` and set **Visibility: Private**.
2. Under **Account settings → Personal access tokens**, create a token with read & write access (`dckr_pat_…`).
3. Push:

```powershell
docker login -u <dockerhub-user>          # paste the access token as the password
docker tag valio-agent-gateway:1.0 <dockerhub-user>/valio-agent-gateway:1.0
docker push <dockerhub-user>/valio-agent-gateway:1.0
```

Use a fixed tag such as `1.0`, not `latest`. Verda's docs advise against `latest` too.

*Alternative: Verda's own registry (private by default).* Create registry credentials on Verda's
**Container Registry** page, then:

```powershell
echo '<SECRET>' | docker login vccr.io/<PROJECT_ID> -u 'vcr-<PROJECT_ID>+<credentials-name>' --password-stdin
docker tag valio-agent-gateway:1.0 vccr.io/<PROJECT_ID>/valio-agent-gateway:1.0
docker push vccr.io/<PROJECT_ID>/valio-agent-gateway:1.0
```

## 3. Environment variables

Generate the secrets once:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"   # run once per *_KEY / password / WEBHOOK_SECRET
python -c "import secrets; print(secrets.token_hex(32))"       # GATEWAY_SIGNING_KEY_HEX (exactly 64 hex chars)
```

| Variable | Required | Value |
|---|---|---|
| `VALIO_API_KEY` | ✅ | Your Junction API key (`X-API-Key` for junction26.valioaimo.fi) |
| `GEMINI_API_KEY` | ✅ | Google AI Studio key (powers the Auditor chat) |
| `GATEWAY_APPROVER_KEY` | ✅ | Random secret: service key for approvals (`X-Approver-Key`) |
| `DASHBOARD_MANAGER_PASSWORD` | ✅ | Replaces the demo password `manager123` (**first start only**, see below) |
| `DASHBOARD_AUDITOR_PASSWORD` | ✅ | Replaces the demo password `auditor123` (**first start only**) |
| `GATEWAY_SIGNING_KEY_HEX` | ✅ | 64 hex chars, ideally from a secret store. Without it the gateway creates `/app/var/signing_key.hex` once and reuses it, so **the `/app/var` volume must be persistent**, or every redeploy rotates the key and earlier signed offers/quotes stop verifying (`UNKNOWN_KEY`) |
| `WEBHOOK_SECRET` | ✅ | Random secret for the HMAC-signed approval webhooks |
| `WEBHOOK_URL` | ✅ | `https://<your-public-host>/v1/webhooks/mock-receiver` (or a real ERP endpoint) |
| `GATEWAY_ADMIN_KEY` | ✅ | Random secret: Valio-side key for `POST /v1/offers/proactive` |
| `GATEWAY_AGENT_KEYS` | ✅ | `<random-key>:hotel-procurement-bot[:<customer-id>],<random-key2>:read-only-analyst` (replaces the `dev-*` keys) |
| `VALIO_CUSTOMER_ID` | recommended | Real customer id from Valio; otherwise `demo-customer` (most products then lack a net price → human approval) |
| `GATEWAY_SEMANTIC` | optional | `1` (default in the image) for semantic search, `0` for lexical only |
| `GEMINI_MODEL` | optional | Override the chat model (default `gemini-3.8-flash`, with automatic fallbacks) |

> Dashboard users are created on the **first** start and stored hashed in the database, so the
> `DASHBOARD_*_PASSWORD` variables must be set **before** the first boot on a fresh volume.

## 4. Deploy on Verda Cloud

### Option A: Verda serverless Containers

Verda Containers are designed for GPU inference endpoints. Before relying on it for the demo,
**verify these three points with Verda** (their docs don't settle them):

1. **CPU-only compute.** The documented compute types are all GPUs, and you are billed per minute while a replica runs.
2. **Public endpoint.** Verda's examples call deployments with `Authorization: Bearer <Inference API key>`.
   The dashboard is opened in a browser and uses its own `Authorization` header for logins, so it only works
   if the deployment can be reached **without** Verda's inference key.
3. **WebSockets.** The live dashboard uses `wss://…/ws`. If they aren't supported, it falls back to polling every 15 s.

Steps (console labels from Verda's docs):

1. **Containers → New deployment**. Give it a name and pick a **Compute Type** (the smallest available).
2. **Container Image:** `docker.io/<dockerhub-user>/valio-agent-gateway` (or the `vccr.io/...` path), **Tag:** `1.0`.
   For a private Docker Hub repo, add registry credentials: your Docker Hub username and the `dckr_pat_…` token.
3. **Exposed HTTP port:** `8000` · **Healthcheck port:** `8000` · **Healthcheck path:** `/health`.
   `/health` returns JSON `{"status": "ok"}`, which Verda treats as healthy. While the catalog loads it reports `starting`.
4. Leave **Start Command** off. The image's own `CMD` starts uvicorn.
5. **Environment Variables:** add everything from the table in section 3.
6. **Storage:** set the deployment's scratch-disk **mount path to `/app/var`**. Verda keeps it when the deployment
   scales to zero, so the database and audit chain survive restarts.
7. **Scaling:** **min replicas 1, max replicas 1.**
   - More than one replica breaks the live WebSocket feed, because each replica has its own hub.
   - Scale-to-zero (min 0) means cold starts during the demo.
8. **Deploy container**, then open the base endpoint URL shown under **Containers API**, adding `/dashboard`.

### Option B: any VM with Docker, including a Verda CPU or GPU instance

This is the most predictable option for a demo: you get a public URL, WebSockets, and no extra auth layer in front.

```bash
docker login -u <dockerhub-user>
docker volume create gateway-data
docker run -d --name gateway --restart unless-stopped \
  -p 80:8000 --env-file gateway.env -v gateway-data:/app/var \
  <dockerhub-user>/valio-agent-gateway:1.0
```

`gateway.env` holds the variables from section 3 (`KEY=value` per line, `chmod 600`). Put HTTPS in
front of it (e.g. Caddy: `caddy reverse-proxy --from your.domain --to :80`). The dashboard then uses `wss://` automatically.

## 5. After deploying

```bash
curl https://<host>/health                     # "status": "ok", "upstream": "live", audit "valid": true
python examples/seed.py --url https://<host>   # populate the dashboard with a week of activity
```

Then sign in at `https://<host>/dashboard` with the manager password you set.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits at start with a SQLite / permission error | The mounted volume isn't writable by the container user (uid 10001). Make the mount writable, or check the platform's volume-ownership settings. |
| Dashboard shows **Disconnected** but data loads | The platform doesn't pass WebSockets. The page falls back to polling every 15 s. |
| Every order needs a human ("no negotiated customer price") | `VALIO_CUSTOMER_ID` isn't set to a real customer. |
| Chat says "Gemini is busy" | Google-side overload. The chat already tries fallback models; ask again after a moment. |
| `"upstream": "mock"` in `/health` | `VALIO_API_KEY` missing. The gateway then runs on simulated stock and prices. |

---
Verda details are taken from Verda's documentation: [Containers overview](https://docs.verda.com/containers/overview/index.md),
[Terraform `verda_container`](https://docs.verda.com/infrastructure-as-code/terraform/containers-containers/),
[Container Registry quickstart](https://docs.verda.com/storage/container-registry/quickstart/index.md),
[Docker Hub tutorial](https://docs.verda.com/containers/tutorials/tutorial-how-to-publish-your-first-docker-image-to-docker-hub/index.md).
