""" Contains the Freshclam Updater Class, which handles the updates of ClamAV's malware database """

import asyncio
import datetime
from .guardian_logger import guardian_logger

class FreshClam:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(FreshClam, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.frequency = None  # Seconds
        self.last_updated = None

    def _update_required(self) -> bool:
        if self.frequency and self.last_updated:
            now = datetime.datetime.now()
            next_update = self.last_updated + datetime.timedelta(seconds=self.frequency)
            return now > next_update
        elif self.frequency and not self.last_updated:
            return True
        elif not self.frequency:
            return True

    async def _update_clamav(self) -> None:
        command = ["freshclam"]  # TODO Add flag methods for customization
        process = await asyncio.create_subprocess_exec(*command)
        stdout, stderr = await process.communicate()
        await process.wait()
        if stdout:
            guardian_logger.info(stdout.decode())
        if stderr:
            guardian_logger.info(stderr.decode())

    async def update(self) -> None:
        if self._update_required():
            await self._update_clamav()
            self.last_updated = datetime.datetime.now()