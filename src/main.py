from fastapi import FastAPI
from fastapi import APIRouter, Depends, Cookie, Header, status, Request, Response
from fastapi.exceptions import RequestValidationError

from tests.util import get_all_src_py_files_hash
from src.api import api_router

from src.common import CustomException

app = FastAPI()

app.include_router(api_router)

@app.exception_handler(CustomException)
async def handle_custom_exception(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "error_msg": exc.error_message,
        },
    )

@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(request: Request, exc: RequestValidationError):
    missing_fields = [
        e["loc"][-1] for e in exc.errors() if e["type"] == "missing"
    ]
    if missing_fields:
        custom_exc = MissingFieldException()
        return JSONResponse(
            status_code=custom_exc.status_code,
            content={
                "error_code": custom_exc.error_code,
                "error_msg": custom_exc.error_message,
            },
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "error_msg": exc.error_message,
        },
    )

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }