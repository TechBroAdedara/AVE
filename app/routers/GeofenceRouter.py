from datetime import datetime
from typing import Annotated, Dict, List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..schemas import GeofenceCreateModel, AttendanceRecordModel, AttendanceRecordOut
from ..database import get_db_session
from ..auth.sessions.sessionDependencies import (
    authenticate_admin_user,
    authenticate_student_user,
    authenticate_user_by_session_token,
)
from ..services import GeofenceService, UserService

DBSessionDep = Annotated[AsyncSession, Depends(get_db_session)]
authenticate_admin = Annotated[dict, Depends(authenticate_admin_user)]
authenticate_student = Annotated[dict, Depends(authenticate_student_user)]


def get_geofence_service(session: DBSessionDep):
    return GeofenceService(session)


GeofenceRouter = APIRouter(prefix="/geofence", tags=["Geofences"])


@GeofenceRouter.post("/create_geofence")
async def create_geofence(
    geofence: GeofenceCreateModel, session: DBSessionDep, admin: authenticate_admin
):
    geofenceService = GeofenceService(session)
    result =  await geofenceService.create_geofence(admin["user_matric"], geofence)
    return result

@GeofenceRouter.get("/get_geofence", dependencies=[Depends(authenticate_admin_user)])
async def get_geofence(
    course_title: str, date: datetime, session: DBSessionDep
):
    """Returns details of geofence for a given course title"""
    geofenceService = GeofenceService(session)
    geofence_response = await geofenceService.get_geofence(course_title, date)
    return geofence_response


@GeofenceRouter.get(
    "/get_geofences", dependencies=[Depends(authenticate_user_by_session_token)]
)
async def get_geofences(session: DBSessionDep):
    """Returns all the geofences created"""
    geofenceService = GeofenceService(session)
    geofences_response = await geofenceService.get_all_geofences()
    return geofences_response


@GeofenceRouter.get("/get_my_geofences")
async def get_my_geofences_created(session: DBSessionDep, admin: authenticate_admin):
    """Returns a list of all geofences created by the given admin"""
    geofenceService = GeofenceService(session)
    geofences_response = await geofenceService.get_all_geofences(admin["user_matric"])
    return geofences_response


@GeofenceRouter.post("/record_attendance")
async def record_attendance(
    session: DBSessionDep,
    attendance: AttendanceRecordModel,
    student: authenticate_student,
):
    geofenceService = GeofenceService(session)
    userService = UserService(session)
    recorded_attendance_response = await geofenceService.record_geofence_attendance(
        user_matric=student["user_matric"],
        attendance=attendance,
        userService=userService,
    )

    return recorded_attendance_response


@GeofenceRouter.get("/get_attendances", response_model=Dict[str, List[AttendanceRecordOut]])
async def get_geofence_attendances(
    fence_code, admin: authenticate_admin, session: DBSessionDep
):
    """Returns the attendances for a given course"""
    geofenceService = GeofenceService(session)
    attendances_response = await geofenceService.get_geofence_attendances(
        fence_code = fence_code, user_id=admin["user_matric"]
    )

    return attendances_response


@GeofenceRouter.put("/deactivate")
async def deactivate_geofence(
    session: DBSessionDep, admin: authenticate_admin, geofence_name: str, date: datetime
):
    geofenceService = GeofenceService(session)
    deactivate_message = await geofenceService.deactivate_geofence(
        geofence_name, date, admin["user_matric"]
    )

    return deactivate_message
