"""Contains the clamav_scanner decorator function for FastAPI Routes"""

import tempfile
from fastapi import File, UploadFile, HTTPException
from guardian import Options
from guardian.scanner import Scanner
import io
import functools


def scan_upload(scanner_options: Options = None):
    if scanner_options is None:
        scanner_options = Options()

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(file: UploadFile = File(...)):
            scanner = Scanner(options=scanner_options)
            bytes_io = io.BytesIO(await file.read())
            bytes_io.seek(0)
            is_clean = await scanner.scan_file(bytes_io)
            if is_clean:
                return await func(file)
            else:
                raise HTTPException(status_code=400, detail="File is infected")

        return wrapper

    return decorator
