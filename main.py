from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, Query, Path as PathArgs
from sqlalchemy.ext.asyncio import AsyncSession
from dbconn import get_db
from sqlalchemy import text, select, update
import pandas as pd
import uuid
from typing import List
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from models import User, File as FileModel
import os
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from fastapi.security import  OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta
import redis.asyncio as redis
import json



pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated = "auto")






# global config
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["http://localhost:3000"],  # React dev server
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)



# ✅ IMPORT File/Form AFTER app definition
from fastapi import File as FastAPIFile, Form, UploadFile
import aiofiles
from pathlib import Path

# JWT Configuration (use .env in production)
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "login")

redis_client = redis.Redis(host = "localhost", port=6379, db=0, decode_responses=True)



class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str 

class UserLogin(BaseModel):
    email: EmailStr
    password: str


def hash_password(password: str) -> str:
    """ hash plain password using pbkdf2_sha256"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """ verify plain password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=" Could not validate credentials",
        headers={"WWW-Authentication": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int  = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    
    return user_id






@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):

    # Check if user email already exists
    result = await db.execute(select(User).where(User.email == user.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail = "Email already registered")
    
    # hashing password

    hash_pwd = hash_password(user.password)

    # create user instance
    new_user = User(name = user.name, email = user.email, password = hash_pwd,
                    status = "active", role = 'user')
    # add and commit to db
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return {"id": new_user.id, "name": new_user.name, "email": new_user.email, "success": True}

@app.post("/login", status_code=status.HTTP_200_OK)
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    # get user by email
    result = await db.execute(select(User).where(User.email == user.email))

    db_user = result.scalar_one_or_none()

    # ✅ Check if user exists FIRST
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if db_user.status != "active":
        raise HTTPException(status_code=404, detail="User not found")

    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create jwt token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {"sub": db_user.email, "user_id": db_user.id},
        expires_delta=access_token_expires
    )

    return {"success": True,
             "message": "login successfully",
                 "access_token": access_token,
                 "token_type": "bearer"}



@app.post("/upload_file", status_code=status.HTTP_200_OK)
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

@app.get("/read_file")
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
            df = pd.read_excel(file_path)
        elif file_format == "parquet":
            df = pd.read_parquet(file_path)
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








@app.get("/view_files")
async def view_files(user_id: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    # Verify user exists
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Get all files for user
    result = await db.execute(select(FileModel).where(FileModel.user_id == user_id))
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

@app.delete("/delete_file/{file_id}", status_code=status.HTTP_200_OK)
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

@app.delete("/delete_user", status_code=status.HTTP_200_OK)
async def delete_user(
        user_id: int = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.id == user_id))

    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Soft delete by updating status
    await db.execute(
        update(User).where(User.id == user_id).values(status = "deleted")
    )
    await db.commit()

    return {
        "message": f"user {user.name} deleted successfully",
        "success": True
    }






    


    

@app.get("/health")
async def read_user(db: AsyncSession = Depends(get_db)):
    try:
        # simple test query to check db connection
        result = await db.execute(text("SELECT 1"))

        # if query executes successfully, db connection is fine
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(status_code = 500, detail = "Database connection failed")

    


