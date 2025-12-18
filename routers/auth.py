from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import EmailStr
from typing import Optional
from datetime import timedelta
from schemas.models import UserOut, TokenOut
from dbconn import get_db
from models import User
from passlib.context import CryptContext
from jose import jwt, JWTError
from sqlalchemy import select, update
from utils.auth import verify_password, create_access_token, hash_password, ACCESS_TOKEN_EXPIRE_MINUTES, get_current_user
from schemas.models import UserCreate, UserLogin, UserOut, TokenOut

router = APIRouter(prefix="/auth", tags = ["auth"])



@router.post("/token", tags=["auth"], summary="Get JWT token (Swagger)")
async def login_for_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """Token endpoint for Swagger UI OAuth2 flow."""
    # Convert username to email lookup (since Swagger sends "username")
    user = await db.execute(select(User).where(User.email == form_data.username))
    db_user = user.scalar_one_or_none()
    
    if not db_user or not verify_password(form_data.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email, "user_id": db_user.id},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds
    }






@router.post(
        "/register",
        status_code=status.HTTP_201_CREATED,
        tags=["auth"],
        summary="Register new user",
        description="Create a new user account with name, email, and password.",
        response_model=UserOut
)
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

    return UserOut(id=new_user.id, name=new_user.name, email=new_user.email, success=True)

@router.post(
        "/login",
        status_code=status.HTTP_200_OK,
        tags = ["auth"],
        summary="User login",
        description="Authenticate user with email and password and return a JWT access token.",
        response_model=TokenOut
)
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

    return TokenOut(success=True, message="login successfully", access_token=access_token, token_type="bearer",)


@router.delete(
    "/delete_user",
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Delete user",
    description="Soft delete the currently authenticated user.",
)
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