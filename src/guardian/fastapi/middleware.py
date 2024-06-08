from starlette.middleware.base import BaseHTTPMiddleware
from guardian.scanner import Scanner
from guardian.logger import GuardianLogger
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import RequestResponseEndpoint

guard_log = GuardianLogger()


class FileUploadScanMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        await (
            request.body()
        )  # DO NOT REMOVE OR ELSE IT DOES NOT WORK AND THROWS 422 I DO NOT KNOW WHY LOL
        if request.method == "POST" and request.headers.get(
            "content-type", ""
        ).startswith("multipart/form-data"):
            form = await request.form()
            for form_field, upload_file in form.items():
                if isinstance(upload_file, UploadFile):
                    virus_was_detected = await self.detect_virus(upload_file)
                    guard_log.debug(msg=f"Virus Detected: {virus_was_detected}")
                    if virus_was_detected:
                        return Response(
                            content="Infected file detected. File upload rejected.",
                            status_code=400,
                        )
        response = await call_next(request)
        return response

    async def detect_virus(self, file: UploadFile):
        scanner = Scanner()
        file.file.seek(0)
        result = await scanner.scan_file(file)
        if not result:
            guard_log.critical(msg=f"File {file.filename} is infected.")
            return True
        file.file.seek(0)
        guard_log.info(msg=f"File {file.filename} is clean.")
        return False

    async def _log_request_debug(request: Request):
        body = await request.body()
        guard_log.debug(msg=f"Request Method: {request.method}")
        guard_log.debug(msg=f"Request URL: {request.url}")
        guard_log.debug(msg=f"Request Headers: {request.headers}")
        guard_log.debug(msg=f"Request Query Parameters: {request.query_params}")
        guard_log.debug(
            msg=f"Request Client Host: {request.client.host if request.client else "Client host unknown"}"
        )
        guard_log.debug(
            msg=f"Request Client Port: {request.client.port if request.client else "Client port unknown"}"
        )
        item_id = request.path_params.get("item_id", "Unknown")
        guard_log.debug(f"Request Path parameter item_id: {item_id}")
        guard_log.debug(msg=f"Request Body: {body}")
