"""Contains the ClamAVScanner class, which handles the actual scanning and database update functionality"""

import asyncio
from .builder import ClamAVScannerOptions
from .update import FreshClam
from io import BytesIO
from .guardian_logger import guardian_logger
class ClamAVScanner:
    def __init__(self, options: ClamAVScannerOptions = ClamAVScannerOptions()):
        self.options = options.build_command_list()

    async def scan_file(self, file: BytesIO):

        # Ensure the signature database is up-to-date before scanning
        await self.update_database()

        # Add the file path to the command
        full_command = self.options +["-"]

        process = await asyncio.create_subprocess_exec(
            *full_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        file.seek(0)
        stdout, stderr = await process.communicate(file.getvalue())
        if stdout:
            guardian_logger.debug(stdout.decode())
        if stderr:
            guardian_logger.debug(stderr.decode())

        if process.returncode == 0:
            guardian_logger.info("No virus detected.")
            return True
        elif process.returncode == 1:
            guardian_logger.warning("Virus detected.")
            return False
        else:
            guardian_logger.error("Error scanning.")
            return False

    async def update_database(self):
        fresh_clam = FreshClam()
        await fresh_clam.update()