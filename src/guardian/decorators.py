"""Contains the clamav_scanner decorator function"""

import tempfile
from fastapi import File, UploadFile, HTTPException
from .options import ClamAVScannerOptions
from .scanner import ClamAVScanner
import io
import functools


def scan_upload(scanner_options: ClamAVScannerOptions = None):
    if scanner_options is None:
        scanner_options = ClamAVScannerOptions()

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(file: UploadFile = File(...)):
            scanner = ClamAVScanner(options=scanner_options)
            bytes_io = io.BytesIO(await file.read())
            bytes_io.seek(0)
            is_clean = await scanner.scan_file(bytes_io)
            if is_clean:
                return await func(file)
            else:
                raise HTTPException(status_code=400, detail="File is infected")

        return wrapper

    return decorator
