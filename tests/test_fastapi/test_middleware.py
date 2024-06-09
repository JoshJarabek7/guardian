import io
from fastapi import FastAPI, File, Response, UploadFile
from fastapi.testclient import TestClient
from hiss.fastapi.middleware import FileUploadScanMiddleware
from hiss.logger import Hisss

guard_log = Hisss()
app = FastAPI()
app.add_middleware(FileUploadScanMiddleware)
client = TestClient(app)


@app.post("/dirty")
async def file_upload_dirty_route(file: UploadFile = File(...)):
    if not file:
        return Response(content="No file provided", status_code=400)
    return Response(content="File uploaded successfully", status_code=200)


@app.post("/clean")
async def file_upload_clean_route(file: UploadFile = File(...)):
    if not file:
        return Response(content="No file provided", status_code=400)
    return Response(content="File uploaded successfully", status_code=200)


def test_clean_file_upload():
    with io.BytesIO(b"hello") as file_data:
        response = client.post(
            "/clean",
            files={"file": ("clean_file.txt", file_data)},
        )
    assert response.status_code == 200
    assert response.text == "File uploaded successfully"


def test_virus_file_upload():
    with io.BytesIO(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ) as file_data:
        response = client.post(
            "/dirty",
            files={
                "file": (
                    "dirty_file.txt",
                    file_data,
                )
            },
        )
    assert response.status_code == 400
    assert response.text == "Infected file detected. File upload rejected."
