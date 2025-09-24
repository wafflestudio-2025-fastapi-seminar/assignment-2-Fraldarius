import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import MissingFieldException
from src.users.errors import InvalidPasswordException
from src.users.errors import InvalidPhoneException
from src.users.errors import InvalidBioException
from src.users.errors import DuplicatedEmailException

from src.common.database import user_db

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v

    @field_validator('email', mode='after')
    def validate_email(cls, v):
        for user in user_db:
            if user["email"] == v:
                raise DuplicatedEmailException()
        return v

    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        phoneNumRegex = re.compile(r"^010-\d{4}-\d{4}$")
        if not phoneNumRegex.match(v):
            raise InvalidPhoneException()
        else:
            return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise InvalidBioException()
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float