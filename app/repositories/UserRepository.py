from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ..schemas.UserSchema import UserCreateModel
from ..models import User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import or_


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_user_by_email_or_matric(
        self, email: str = None, matric: str = None
    ) -> User:
        stmt = (
            select(User)
            .options(selectinload(User.attendances))
            .filter(or_(User.email == email, User.user_matric == matric))
        )
        result = await self.session.execute(stmt)
        user = result.scalars().first()

        return user

    async def create_new_user(self, user: UserCreateModel, password_hash: str):
        new_user = User(
            email=user.email,
            user_matric=user.user_matric,
            role=user.role,
            username=user.username,
            hashed_password=password_hash,
        )

        self.session.add(new_user)
        await self.session.commit()
        return {"message": "Successfully added user. You can now login"}

    async def change_user_password(self, user_email: str, new_hashed_password: str):
        user = await self.get_user_by_email_or_matric(email=user_email)

        user.hashed_password = new_hashed_password
        await self.session.commit()
        
        return {"message": "Successfully changed password"}
