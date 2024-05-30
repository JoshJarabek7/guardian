"""Contains the clamav_scanner decorator function"""

import tempfile
from fastapi import File, UploadFile, HTTPException
from .builder import ClamAVScannerBuilder


def clamav_scanner(scanner_builder: ClamAVScannerBuilder = None):
    if scanner_builder is None:
        scanner_builder = ClamAVScannerBuilder()

    def decorator(func):
        async def wrapper(file: UploadFile = File(...)):
            scanner = scanner_builder.build()
            if scanner.in_memory:
                file_content = await file.read()
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(file_content)
                    is_clean = await scanner.scan_file(temp_file.name)
            else:
                file_path = scanner.file_path or file.filename
                with open(file_path, "wb") as f:
                    f.write(await file.read())
                is_clean = await scanner.scan_file(file_path)

            if is_clean:
                return await func(file)
            else:
                raise HTTPException(status_code=400, detail="File is infected")

        return wrapper

    return decorator
