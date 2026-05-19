from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess, os, hashlib, uuid

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...)):
    # Save file
    case_id = str(uuid.uuid4())[:8]
    apk_path = f"{UPLOAD_DIR}/{case_id}.apk"
    content = await file.read()

    with open(apk_path, "wb") as f:
        f.write(content)

    # Hash it
    sha256 = hashlib.sha256(content).hexdigest()

    # Unpack with apktool
    output_dir = f"{UPLOAD_DIR}/{case_id}_unpacked"
    subprocess.run(["apktool", "d", apk_path, "-o", output_dir, "-f"], 
                   capture_output=True)

    return {
        "case_id": case_id,
        "filename": file.filename,
        "sha256": sha256,
        "size_bytes": len(content),
        "status": "unpacked"
    }

@app.get("/api/health")
def health():
    return {"status": "ok"}