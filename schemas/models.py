
from pydantic import BaseModel, EmailStr



class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str 

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    success: bool

    class config:
        from_attributes = True

class TokenOut(BaseModel):
    success: bool
    message: str
    access_token: str
    token_type: str

