from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routers import StudentRouter

from .routers import AdminRouter
from .routers import GeneralUserRouter
from .database import sessionmanager
from .auth.AuthRouter import AuthRouter

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Function that handles startup and shutdown events.
    To understand more, read https://fastapi.tiangolo.com/advanced/events/
    """
    yield
    if sessionmanager._engine is not None:
        # Close the DB connection
        await sessionmanager.close()


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

app.include_router(GeneralUserRouter)
app.include_router(AuthRouter)
app.include_router(AdminRouter)
app.include_router(StudentRouter)