from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File as FastAPIFile, status, Path as PathArgs
from sqlalchemy.ext.asyncio import AsyncSession
from dbconn import get_db
from models import User, File as FileModel
from utils.auth import get_current_user
from sqlalchemy import select, update
import uuid
import os
import aiofiles
import pandas as pd
import json
from pathlib import Path
import redis.asyncio as redis



router = APIRouter(prefix="/files", tags=["files"])

# global config
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


redis_client = redis.Redis(host = "localhost", port=6379, db=0, decode_responses=True)






@router.post(
        "/upload_file",
        status_code=status.HTTP_200_OK,
        tags = ["files"],
        summary= "Upload a file",
        description="Upload csv, excel, or parquet file for the authenticate user."
)
async def upload_file(
                      file: UploadFile = FastAPIFile(...),
                      user_id: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)
                      ):
    # Verify user exists
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate file type
    allowed_formats = ['.csv', '.xlsx', '.xls', '.parquet']

    file_extension = Path(file.filename).suffix.lower()
    if file_extension not in allowed_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Only {', '.join(allowed_formats)} files allowed"
        )
    
    # Generate unique filename
    file_format = file_extension.lstrip(".")
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    # save file asynchronously
    content = await file.read()
    async with aiofiles.open(file_path, "wb") as buffer:
        await buffer.write(content)

    file_size = len(content)

    # quick validation of file readability
    try:
        if file_format == ".csv":
            pd.read_csv(file_path, nrows=1)
        elif file_format in [".xlsx" , ".xls"]:
            pd.read_excel(file_path, nrows=1)
        elif file_format == ".parquet":
            pd.read_parquet(file_path)
    except Exception:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=400, detail="Invalid or corrupted file")
    
    # Create file record in database
    new_file = FileModel(
        user_id = user_id,
        file_name = file.filename,
        file_size = file_size,
        file_path = file_path,
        file_format = file_format,
        status = "uploaded"
    )

    db.add(new_file)
    await db.commit()
    await db.refresh(new_file)

    return {
        "file_id": new_file.id,
        "file_name": new_file.file_name,
        "file_format": new_file.file_format,
        "file_size": f"{file_size/ (1024*1024):.2f} MB",
        "status": new_file.status,
        "message": "File uploaded successfully",
        "success": True
    }

@router.get(
        "/read_file",
        tags = ["files"],
        summary="Read file rows",
        description="read a specific row by ID with pagination, returing rows as json.",
)
async def read_file(file_id: int = Query(..., description="ID of the file to read"),
                    page: int = Query(1, ge=1),
                    page_size: int = Query(100, ge=10, le= 1000),
                    user_id: User = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    # get file record from db
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    db_file = result.scalar_one_or_none()

    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = db_file.file_path

    if not file_path:
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # decide which format to use
    file_format = db_file.file_format

    # cache key
    cache_key = f"file:{file_id}:page:{page}:size:{page_size}"

    # Try cache first
    cached_data = await redis_client.get(cache_key)

    if cached_data:
        return json.loads(cached_data)

    # Read file using pandas (small/medium files)

    try:
        if file_format == "csv":
            df = pd.read_csv(file_path, nrows=page_size*(page))
            df = df.iloc[(page-1)*page_size:page*page_size]
        elif file_format in ("xls", "xlsx"):
            # Read entire Excel file (unavoidable for Excel)
            df = pd.read_excel(file_path)
            total_rows = len(df)
            # NOW SLICE IT! This was missing
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            df = df.iloc[start_idx:end_idx]
            
        elif file_format == "parquet":
            df = pd.read_parquet(file_path)
            total_rows = len(df)
            # Slice for parquet too
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            df = df.iloc[start_idx:end_idx]
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to read file")
    
    
    # Return as json (list of rows)
    response =  {
        "file_id": db_file.id,
        "total_rows": len(df),
        "page": page,
        "page_size": page_size,
        "file_name": db_file.file_name,
        "file_format": db_file.file_format,
        "rows": df.to_dict(orient="records"),
        "success": True
    }

    await redis_client.setex(cache_key, 3600, json.dumps(response))

    return response








@router.get(
    "/view_files",
    tags=["files"],
    summary="List user files",
    description="Return all files uploaded by the authenticated user.",
)
async def view_files(user_id: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    # Verify user exists
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Get all files for user
    result = await db.execute(select(FileModel).where(FileModel.user_id == user_id, FileModel.status == "uploaded"))
    files = result.scalars().all()

    # Format response
    return [
        {
            "file_id": f.id,
            "file_name": f.file_name,
            "file_format": f.file_format,
            "file_size": f.file_size,
            "status": f.status,
            "uploaded_at": f.created_at.isoformat() if f.created_at else None
        }
        for f in files
    ]

@router.delete(
    "/delete_file/{file_id}",
    status_code=status.HTTP_200_OK,
    tags=["files"],
    summary="Delete file",
    description="Soft delete a file record and remove the file from disk.",
)
async def delete_file(
        file_id: int = PathArgs(..., description="ID of the file to delete"),
        db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))

    file = result.scalar_one_or_none()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    # Delete file from disk if exists
    if os.path.exists(file.file_path):
        try:
            os.remove(file.file_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete file from disk: {e}")
    # soft delete: update the status to deleted
    await db.execute(
        update(FileModel).where(FileModel.id == file_id).values(status = "deleted")
    )
    await db.commit()

    return {
        "message": f"File {file.file_name} deleted successfully",
        "success": True
    }
