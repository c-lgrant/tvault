import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import WEBHOOK_EXTERNAL_URL, WEBHOOK_VERSION, http_client, log
from middleware import RequestLoggingMiddleware
from routes import all_routers
from store import store


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not store.get("is_configured"):
        url = WEBHOOK_EXTERNAL_URL or f"http://localhost:{os.environ.get('PORT', '8080')}"
        log.info("------------------------------------------------------------")
        log.info("WEBHOOK NOT CONFIGURED")
        log.info("Please open %s/bind in your browser to connect to Token Vault", url)
        log.info("------------------------------------------------------------")
    yield
    await http_client.aclose()


app = FastAPI(
    title="TokenVault webhook service (sovereign)",
    version=WEBHOOK_VERSION,
    lifespan=lifespan,
)

app.add_middleware(RequestLoggingMiddleware)

for router in all_routers:
    app.include_router(router)


# ── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
