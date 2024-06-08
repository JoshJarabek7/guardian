from fastapi import Request, UploadFile, Response
from starlette.middleware.base import BaseHTTPMiddleware
from guardian.scanner import Scanner
from guardian.logger import GuardianLogger
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.middleware.base import _StreamingResponse

guard_log = GuardianLogger()


class FileUploadScanMiddleware(BaseHTTPMiddleware):
    def __init__(self, app=None):
        super().__init__(app)
        self.remove_infected = True
        self.do_not_continue_logic_after_detection = True

    async def dispatch(self, request: Request, call_next):
        try:
            print(await request.body())
            if request.headers.get("content-type", "").startswith(
                "multipart/form-data"
            ):
                form = await request.form()
                files = []
                file_map = {}

                for name, item in form.items():
                    if isinstance(item, (StarletteUploadFile, UploadFile)):
                        files.append(item)
                        file_map[name] = item
                guard_log.critical(msg=f"FILES: {files}")
                for file in files:
                    virus_was_detected = await self.detect_virus(file)
                    guard_log.critical(msg=f"Virus was detected: {virus_was_detected}")
                    if (
                        virus_was_detected
                        and self.do_not_continue_logic_after_detection
                    ):
                        guard_log.critical(msg=f"TRIGGERS BOTH {virus_was_detected}")
                        return Response(
                            content="Infected file detected. File upload rejected.",
                            status_code=400,
                        )

            response = await call_next(request)
            guard_log.critical(msg=f"RESPONSE {response}")
            guard_log.critical(msg=f"STATUS CODE {response.status_code}")
            # guard_log.critical(msg=f"BODY {response.body}")
            guard_log.critical(msg=f"MEDIA TYPE {response.media_type}")
            guard_log.critical(msg=f"RESPONSE DATA TYPE: {type(response)}")
            if isinstance(response, _StreamingResponse):
                return response

            return response
        except Exception as e:
            guard_log.critical(f"EXCEPTION: {e}")
            return Response(content="Internal Server Error", status_code=500)

    async def detect_virus(self, file: UploadFile):
        scanner = Scanner()
        file.file.seek(0)  # Ensure the file pointer is at the start
        result = await scanner.scan_file(file)
        if not result:
            guard_log.critical(msg=f"File {file.filename} is infected.")
            return True
        file.file.seek(0)  # Reset the file pointer to allow re-reading
        guard_log.info(msg=f"File {file.filename} is clean.")
        return False
