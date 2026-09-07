from fastapi import APIRouter, HTTPException
from app.forensic.case_manager import create_case, get_case, list_cases
from app.models.forensic import CaseSeverity, ForensicCase

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.get("", response_model=list[ForensicCase])
def cases() -> list[ForensicCase]:
    return list_cases()


@router.post("", response_model=ForensicCase)
def new_case(title: str, description: str = "", severity: CaseSeverity = CaseSeverity.MEDIUM) -> ForensicCase:
    return create_case(title, description, severity)


@router.get("/{case_id}", response_model=ForensicCase)
def case_detail(case_id: str) -> ForensicCase:
    case = get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case
