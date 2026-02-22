from fastapi import APIRouter, UploadFile, File
from backend.services.scan_service import run_scan
from backend.scanner.static_scanner import scan_code_for_crypto

router = APIRouter()


@router.post("/scan")
async def scan_code(file: UploadFile = File(...)):
    content = await file.read()
    code = content.decode("utf-8")

    findings = scan_code_for_crypto(code)

    return run_scan(findings)