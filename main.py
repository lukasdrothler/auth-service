
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from contextlib import asynccontextmanager

from src.dependencies import setup_dependencies
import src.routers.token as token
import src.routers.user as user
import src.routers.stripe as stripe

import os
import logging
import uvicorn


load_dotenv()
is_dev = False

try:
    if os.getenv('CURRENT_ENV') == 'development':
        is_dev = True
except KeyError:
    pass

if is_dev:
    log_level = logging.INFO
    hot_reload = True
    docs_url = "/docs"
    redoc_url = "/redoc"
else:
    log_level = logging.WARNING
    hot_reload = False
    docs_url = None
    redoc_url = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_dependencies()
    yield


app = FastAPI(
        title="Auth Service",
        description="Authentication service for managing users and tokens",
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=lifespan,
    )

logging.basicConfig(
    level=log_level,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S'
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(token.router)
app.include_router(user.router)
app.include_router(stripe.router)


if __name__ == "__main__":
    uvicorn.run("main:app", host=os.getenv("AUTH_SVC_HOST", "0.0.0.0"), port=int(os.getenv("AUTH_SVC_PORT", 8007)), reload=hot_reload)  # nosec