from datetime import datetime, timezone
import logging
import random
import string
from typing import Optional
from zoneinfo import ZoneInfo
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..schemas import GeofenceCreateModel, AttendanceRecordModel

from ..services import UserService
from ..repositories import GeofenceRepository
from ..utils.GeofenceUtils import check_user_in_circular_geofence


logger = logging.getLogger("uvicorn")


class GeofenceService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.geofenceRepository = GeofenceRepository(self.session)

    async def create_geofence(
        self,
        creator_matric: str,
        geofence: GeofenceCreateModel,
    ):  # SINGULAR
        characters = string.ascii_letters + string.digits
        fence_code = "".join(random.choice(characters) for _ in range(6)).lower()

        existing_geofence = await self.geofenceRepository.get_geofence(
            geofence.name, geofence.start_time
        )
        if existing_geofence:
            raise HTTPException(
                status_code=400,
                detail="Geofence with this name already exists for today",
            )

        start_time_utc = geofence.start_time.astimezone(ZoneInfo("UTC"))
        end_time_utc = geofence.end_time.astimezone(ZoneInfo("UTC"))
        NOW = datetime.now(ZoneInfo("UTC"))
        if start_time_utc >= end_time_utc:
            raise HTTPException(
                status_code=400,
                detail="Invalid duration for geofence. Please adjust duration and try again.",
            )

        if end_time_utc < NOW:
            raise HTTPException(
                status_code=400, detail="End time cannot be in the past."
            )

        added_geofence = await self.geofenceRepository.create_geofence(
            geofence, fence_code, creator_matric, start_time_utc, end_time_utc, NOW
        )

        return {"Code": fence_code, "name": added_geofence.name}

    async def get_all_geofences(self, user_id: Optional[str] = None):  # PLURAL
        if user_id is not None:
            geofences = await self.geofenceRepository.get_all_geofences_by_user(user_id)
        else:
            geofences = await self.geofenceRepository.get_all_geofences()

        if not geofences:
            raise HTTPException(status_code=404, detail="No geofences found")
        return geofences

    async def get_geofence(self, course_title: str, date: datetime):  # SINGULAR
        try:
            geofence = await self.geofenceRepository.get_geofence(course_title, date)
            if geofence:
                return geofence
            else:
                raise HTTPException(
                    status_code=404,
                    detail=f"No geofence found with name {course_title} at date {date}",
                )
        except Exception as e:
            logger.error(f"Something went wrong in fetching geofence")
            logger.error(str(e))

            raise HTTPException(
                status_code=500, detail="Something went wrong. Contact admin."
            )

    async def get_geofence_attendances(
        self, course_title: str, date: datetime, user_id: str
    ):
        geofence = await self.get_geofence(course_title, date)
        if geofence.creator_matric != user_id:
            raise HTTPException(
                status_code=403,
                detail="You are not authorized to view this geofence's attendance.",
            )

        try:
            if geofence and geofence.student_attendances:
                return geofence.student_attendances
            else:
                return

        except Exception as e:
            logger.error(f"Something went wrong in fetching geofence attendances")
            logger.error(str(e))

            raise HTTPException(
                status_code=500, detail="Something went wrong. Contact admin."
            )

    async def record_geofence_attendance(
        self,
        attendance: AttendanceRecordModel,
        user_matric: str,
        userService: UserService,
    ):
        user = await userService.get_user_by_email_or_matric(matric=user_matric)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        geofence = await self.geofenceRepository.get_geofence_by_fence_code(
            attendance.fence_code
        )
        if not geofence:
            raise HTTPException(
                status_code=404,
                detail=f"Invalid fence code: {attendance.fence_code}",
            )

        if geofence.status.lower() != "active":
            raise HTTPException(
                status_code=403, detail="Geofence is not active for attendance."
            )

        matric_fence_code = geofence.fence_code + user["user_matric"]
        existing_record = await self.geofenceRepository.get_attendance_record(
            matric_fence_code
        )
        if existing_record:
            raise HTTPException(
                status_code=403,
                detail="You have already recorded attendance for this class",
            )

        if not check_user_in_circular_geofence(
            attendance.lat, attendance.long, geofence
        ):
            raise HTTPException(
                status_code=403,
                detail="User is not within geofence, attendance not recorded",
            )
        try:

            await self.geofenceRepository.record_geofence_attendance(
                attendance=attendance,
                user_matric=user["user_matric"],
                geofence_name=geofence.name,
                matric_fence_code=matric_fence_code,
            )
            return {"message": "Attendance recorded successfully"}
        except Exception as e:
            logger.error(e)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    async def deactivate_geofence(
        self, geofence_name: str, date: datetime, user_matric: str
    ):
        geofence = await self.geofenceRepository.get_geofence(geofence_name, date)
        if not geofence:
            raise HTTPException(
                status_code=404, detail=f"Geofence {geofence_name} not found."
            )
        if geofence.status == "inactive":
            raise HTTPException(status_code=400, detail="Geofence is already inactive")
        if user_matric != geofence.creator_matric:
            raise HTTPException(
                status_code=401,
                detail="You don't have permission to delete this class as you are not the creator.",
            )
        try:
            await self.geofenceRepository.deactivate_geofence(
                geofence_name=geofence.name, date=date
            )
            return {"message": "Geofence deactivated successfully"}
        except Exception as e:
            logger.error(str(e))
            raise HTTPException(status_code=500, detail="Something went wrong")
