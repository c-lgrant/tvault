import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import WEBHOOK_VERSION, http_client
from middleware import RequestLoggingMiddleware
from routes import all_routers


@asynccontextmanager
async def lifespan(app: FastAPI):
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
