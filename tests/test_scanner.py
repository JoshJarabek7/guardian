import tempfile
import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, UploadFile, File
from guardian.decorators import clamav_scanner
from guardian.scanner import ClamAVScanner

app = FastAPI()


@app.post("/upload")
@clamav_scanner()
async def upload_file(file: UploadFile = File(...)):
    return {"filename": file.filename}


client = TestClient(app)


async def mock_scan_file(self, file_path):
    return True


@pytest.mark.asyncio
async def test_clean_file_upload(monkeypatch):
    monkeypatch.setattr(ClamAVScanner, "scan_file", mock_scan_file)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"Clean file content")
        temp_file.seek(0)

        response = client.post(
            "/upload", files={"file": ("clean_file.txt", temp_file, "text/plain")}
        )
        assert response.status_code == 200
        assert response.json() == {"filename": "clean_file.txt"}


@pytest.mark.asyncio
async def test_infected_file_upload(monkeypatch):
    async def mock_scan_file(self, file_path):
        return False

    monkeypatch.setattr(ClamAVScanner, "scan_file", mock_scan_file)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"Infected file content")
        temp_file.seek(0)

        response = client.post(
            "/upload", files={"file": ("infected_file.txt", temp_file, "text/plain")}
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "File is infected"}
