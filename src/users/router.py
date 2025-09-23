from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.common.custom_exception import CustomException

from src.auth.router import decode_token, extract_token_from_header

import bcrypt
from fastapi.responses import JSONResponse

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    user_id = len(user_db) + 1

    response = UserResponse(
        user_id=user_id,
        email=request.email,
        name=request.name,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio,
    )

    b = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())

    newUser = {
      "user_id": user_id,
      "email": request.email,
      "hashed_password": b,
      "name": request.name,
      "phone_number": request.phone_number,
      "height": request.height,
      "bio": request.bio,
    }

    user_db.append(newUser)
    
    return response.model_dump(exclude_none=True)

@user_router.get("/me")
def get_user_info(sid: str | None = Cookie(default=None), Authorization: str | None = Header(default=None),):
    # 1. Session-based authentication
    if sid:
        session = session_db.get(sid)
        if not session or session["expire"] < datetime.now(timezone.utc):
            raise CustomException(
                status_code=401,
                error_code="ERR_006",
                error_message="INVALID SESSION",
            )
        user = next((u for u in user_db if u["user_id"] == session["user_id"]), None)
        if not user:
            raise CustomException(
                status_code=401,
                error_code="ERR_006",
                error_message="INVALID SESSION",
            )
        return UserResponse(**user).model_dump(exclude={"hashed_password"})

    # 2. Token-based authentication
    if Authorization:
        token = extract_token_from_header(Authorization)
        if token in blocked_token_db:
            raise CustomException(
                status_code=401,
                error_code="ERR_008",
                error_message="INVALID TOKEN",
            )

        payload = decode_token(token)
        user_id = int(payload.get("sub"))
        user = next((u for u in user_db if u["user_id"] == user_id), None)
        if not user:
            raise CustomException(
                status_code=401,
                error_code="ERR_008",
                error_message="INVALID TOKEN",
            )
        return UserResponse(**user).model_dump(exclude={"hashed_password"})

    # 3. 둘 다 없는 경우
    raise CustomException(
        status_code=401,
        error_code="ERR_009",
        error_message="UNAUTHENTICATED",
    )