from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from dbconn import get_db

router = APIRouter(tags=["system"])


@router.get(
    "/health",
    tags=["system"],
    summary="Health check",
    description="Check application and database connectivity.",
)
async def read_user(db: AsyncSession = Depends(get_db)):
    try:
        # simple test query to check db connection
        result = await db.execute(text("SELECT 1"))

        # if query executes successfully, db connection is fine
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(status_code = 500, detail = "Database connection failed")