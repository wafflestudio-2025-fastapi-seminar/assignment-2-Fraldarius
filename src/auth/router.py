import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Cookie, Header, status, Request, Response
from fastapi.responses import JSONResponse

from src.common.database import blocked_token_db, session_db, user_db

from src.common import CustomException
from src.users.errors import MissingFieldException

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

def create_token(user_id: int, minutes: int):
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {
        "sub": str(user_id),
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), expire


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise CustomException(
            status_code=401,
            error_code="ERR_008",
            error_message="INVALID TOKEN"
        )
    except jwt.InvalidTokenError:
        raise CustomException(
            status_code=401,
            error_code="ERR_008",
            error_message="INVALID TOKEN"
        )


def extract_token_from_header(auth_header: str | None):
    if not auth_header:
        raise CustomException(
            status_code=401,
            error_code="ERR_009",
            error_message="UNAUTHENTICATED"
        )
    if not auth_header.startswith("Bearer "):
        raise CustomException(
            status_code=400,
            error_code="ERR_007",
            error_message="BAD AUTHORIZATION HEADER"
        )
    return auth_header.split(" ")[1]

@auth_router.post("/token")
def login_for_tokens(request: dict):
    email = request.get("email")
    password = request.get("password")

    if not email or not password:
        raise MissingFieldException()

    # 유저 찾기
    user = next((u for u in user_db if u["email"] == email), None)
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["hashed_password"]):
        raise CustomException(
            status_code=401,
            error_code="ERR_010",
            error_message="INVALID ACCOUNT"
        )

    access_token, _ = create_token(user["user_id"], SHORT_SESSION_LIFESPAN)
    refresh_token, refresh_exp = create_token(user["user_id"], LONG_SESSION_LIFESPAN)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@auth_router.post("/token/refresh")
def refresh_tokens(Authorization: str | None = Header(default=None)):
    token = extract_token_from_header(Authorization)

    if token in blocked_token_db:
        raise CustomException(
            status_code=401,
            error_code="ERR_008",
            error_message="INVALID TOKEN"
        )

    payload = decode_token(token)
    user_id = payload.get("sub")
    exp = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)

    # 기존 refresh_token 블랙리스트에 추가
    blocked_token_db[token] = exp

    access_token, _ = create_token(int(user_id), SHORT_SESSION_LIFESPAN)
    refresh_token, refresh_exp = create_token(int(user_id), LONG_SESSION_LIFESPAN)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@auth_router.delete("/token")
def logout(Authorization: str | None = Header(default=None)):
    token = extract_token_from_header(Authorization)
    payload = decode_token(token)
    exp = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)

    # refresh_token 블랙리스트에 저장
    blocked_token_db[token] = exp
    return JSONResponse(status_code=204, content=None)


@auth_router.post("/session", status_code=status.HTTP_200_OK)
def login_session(request: dict, response: Response):
    email = request.get("email")
    password = request.get("password")

    if not email or not password:
        raise MissingFieldException()

    # finding user
    user = None
    for u in user_db:
        if u["email"] == email:
            user = u
    
    # no user, or not authenticated
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["hashed_password"]):
        raise CustomException(
            status_code=401,
            error_code="ERR_010",
            error_message="INVALID ACCOUNT"
        )

    # create session
    sid = str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN)

    session_db[sid] = {
        "user_id": user["user_id"],
        "expire": expire
    }

    # Set sid as client's cookie
    response.set_cookie(
        key="sid",
        value=sid,
        httponly=True,
        max_age=LONG_SESSION_LIFESPAN * 60,  # seconds
        samesite="lax"
    )

    return JSONResponse(status_code=200, content=None)

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def logout_session(request: Request, response: Response):
    sid = request.cookies.get("sid")

    if sid:
        # delete sid cookie
        response.delete_cookie(
            key="sid",
            httponly=True,
            samesite="lax"
        )

        # remove session
        if sid in session_db:
            del session_db[sid]

    # ✅ 그대로 response 리턴 (새 JSONResponse 만들지 않음)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response