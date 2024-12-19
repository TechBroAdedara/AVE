from typing import Annotated
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routers import GeofenceRouter, StudentRouter
from app.utils.APIKeys import get_api_key

from .routers import AdminRouter
from .routers import GeneralUserRouter
from .database import sessionmanager, Base
from .auth.AuthRouter import AuthRouter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Function that handles startup and shutdown events.
    To understand more, read https://fastapi.tiangolo.com/advanced/events/
    """
     # Startup logic: Create database tables
    async with sessionmanager._engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        
    yield
    if sessionmanager._engine is not None:
        # Close the DB connection
        await sessionmanager.close()

api_key_dependency = Annotated[str, Depends(get_api_key)]

app = FastAPI(
    title="Ave Geofencing",
    description="A smart solution for student attendance",
    version="V1",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Just for Development. Would be changed later.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def index( _ : api_key_dependency):
    return "Hello"

app.include_router(GeneralUserRouter)
app.include_router(AuthRouter)
app.include_router(AdminRouter)
app.include_router(StudentRouter)
app.include_router(GeofenceRouter)