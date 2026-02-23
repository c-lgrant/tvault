from .registration import router as registration_router
from .direct_access import router as direct_access_router
from .proxy import router as proxy_router
from .refresh import router as refresh_router
from .metadata import router as metadata_router

all_routers = [
    registration_router,
    direct_access_router,
    proxy_router,
    refresh_router,
    metadata_router,
]
