"""File upload ingestion (EML/MBOX/MSG) via FastAPI."""
from fastapi import APIRouter, File, UploadFile

from app.ingest.ingest_service import ingest_email
from app.models.email_record import EmailRecord, EmailSource

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/upload", response_model=EmailRecord)
async def upload_email(file: UploadFile = File(...)) -> EmailRecord:
    """Ingest a single uploaded email file (.eml/.msg/.mbox)."""
    raw = await file.read()
    return ingest_email(raw, EmailSource.UPLOAD, metadata={"filename": file.filename})
