"""Contains the ClamAVScanner class, which handles the actual scanning and database update functionality"""

import asyncio
from .builder import ClamAVScannerOptions
from .update import FreshClam

class ClamAVScanner:
    def __init__(self, options: ClamAVScannerOptions = ClamAVScannerOptions()):
        self.options = options

    async def scan_file(self, file_path):

        full_command = self.options + [file_path]

        process = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return True
        else:
            return False

    async def update_database(self):
        fresh_clam = FreshClam()
        await fresh_clam.update()