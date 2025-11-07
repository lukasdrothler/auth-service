
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.dependencies import *
import src.routers.token as token
import src.routers.user as user

import logging
import uvicorn

from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S'
)

load_dotenv()
setup_dependencies(
    access_token_expire_minutes=30,
    refresh_token_expire_days=30,
)

app = FastAPI(
    title="Auth Service API",
    description="API for Auth Service",
    # docs_url=None,
    # redoc_url=None,
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


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)