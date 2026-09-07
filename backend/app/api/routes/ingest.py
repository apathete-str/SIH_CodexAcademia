from fastapi import APIRouter, File, UploadFile
from app.ingest.ingest_service import ingest_email
from app.models.email_record import EmailSource
from app.services.pipeline import AnalysisResult, analyze_email

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_upload(file: UploadFile = File(...)) -> AnalysisResult:
    raw = await file.read()
    email = ingest_email(raw, EmailSource.UPLOAD, {"filename": file.filename})
    return analyze_email(email)
