# test_scanner.py

import pytest
import asyncio
from io import BytesIO
from unittest.mock import patch, AsyncMock
from hiss.scanner import Scanner
from hiss.update import FreshClam


@pytest.mark.asyncio
async def test_update_database():
    scanner = Scanner()
    with patch.object(FreshClam, "update", new_callable=AsyncMock) as mock_update:
        await scanner.update_database()
        mock_update.assert_called_once()


@pytest.mark.asyncio
async def test_scan_file_no_virus():
    scanner = Scanner()
    file_data = BytesIO(b"Test file content")
    clean_file = await scanner.scan_file(file_data)
    assert clean_file is True


@pytest.mark.asyncio
async def test_scan_file_with_virus():
    scanner = Scanner()

    # The universal trigger for positive virus
    virus_signature = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    file_data = BytesIO(virus_signature)

    clean_file = await scanner.scan_file(file_data)
    assert clean_file is False


@pytest.mark.asyncio
async def test_scan_file_error():
    scanner = Scanner()
    test_file = BytesIO(b"Test file content")

    with patch.object(
        FreshClam, "update", new_callable=AsyncMock
    ) as mock_update, patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"Some error occurred")
        mock_process.returncode = 2
        mock_subprocess.return_value = mock_process

        result = await scanner.scan_file(test_file)
        mock_update.assert_called_once()
        mock_subprocess.assert_called_once_with(
            *scanner.options + ["-"],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert result is False
