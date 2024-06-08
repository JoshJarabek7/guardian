"""Contains the ClamAVScanner class, which handles the actual scanning and database update functionality"""

import asyncio
import inspect
from io import BytesIO

from guardian.logger import GuardianLogger
from .update import FreshClam
from guardian import Options
from fastapi import UploadFile

guard_log = GuardianLogger()


class Scanner:
    """Scanner class for scanning files for malware.

    Attributes:
        - options (ClamAVScannerOptions): The options/flags to pass to the scanner (default: ClamAVScannerOptions())
    """

    def __init__(
        self,
        options: Options = Options(),
    ):
        self.options = options.build_command_list()

    async def scan_file(self, file: BytesIO | UploadFile):
        """Scans a BytesIO object for malware.

        Args:
            file (BytesIO): The BytesIO object containing the file to scan.

        Returns:
            bool: Returns True if file is clean, else False
        """
        # Ensure the signature database is up-to-date before scanning
        await self.update_database()

        # Add the file path to the command
        full_command = self.options + ["-"]

        process = await asyncio.create_subprocess_exec(
            *full_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if inspect.iscoroutinefunction(file.seek):
            guard_log.critical(msg="COROUTINE")
            await file.seek(0)
            stdout, stderr = await process.communicate(await file.read())

        else:
            guard_log.critical(msg="NOT COROUTINE")
            file.seek(0)
            stdout, stderr = await process.communicate(file.getvalue())

        if stdout:
            guard_log.debug(msg=stdout.decode())
        if stderr:
            guard_log.debug(msg=stderr.decode())

        if process.returncode == 0:
            guard_log.info(msg="No virus detected.")
            return True
        elif process.returncode == 1:
            guard_log.warning(msg="Virus detected.")
            return False
        else:
            guard_log.error(msg="Error scanning.")
            return False

    async def update_database(self):
        fresh_clam = FreshClam()
        await fresh_clam.update()
