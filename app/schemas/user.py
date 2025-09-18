from pydantic import BaseModel, EmailStr

class RegisterSchema(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    phone: str
    password: str

class EmailSchema(BaseModel):
    email: EmailStr

class OtpVerifySchema(BaseModel):
    email: EmailStr
    otp: str


class ProfileUpdate(BaseModel):
    firstName: str | None = None
    lastName: str | None = None
    email: EmailStr | None = None
    phone: str | None = None


class ProfileOut(BaseModel):
    firstName: str | None = None
    lastName: str | None = None
    email: EmailStr
    phone: str | None = None


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class PasswordChange(BaseModel):
    currentPassword: str
    newPassword: str

