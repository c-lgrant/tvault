import os

from fastapi import FastAPI

from config import WEBHOOK_VERSION
from middleware import RequestLoggingMiddleware
from routes import all_routers

app = FastAPI(
    title="TokenVault webhook service (sovereign)",
    version=WEBHOOK_VERSION,
)

app.add_middleware(RequestLoggingMiddleware)

for router in all_routers:
    app.include_router(router)


# ── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
