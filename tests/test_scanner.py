import pytest
from unittest.mock import AsyncMock, patch
from guardian.scanner import ClamAVScanner  # Adjust import path as necessary
from guardian.decorators import scan_upload
from fastapi import UploadFile
from io import BytesIO

"""TODO: Build tests"""