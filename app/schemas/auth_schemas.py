from typing import Optional, Dict
from pydantic import BaseModel, EmailStr

# untuk daftar
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    
class RegisterResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict]=None
    
# untuk login
class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_response: Optional[str] = None


class LoginResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict] = None

# token provider
class TokenRequest(BaseModel):
    username: str

class TokenResponse(BaseModel):
    token: str
    token_type: str
    expires_at: int
    
class ForgetPasswordRequest(BaseModel):
    email: EmailStr
    
class ForgetPasswordResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict]=None
    
# reset password
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str
    
class ResetPasswordResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict]=None
    
# change password
class ChangePasswordRequest(BaseModel):
    user_id: int
    old_password: str
    new_password: str
    confirm_password: str
    
class ChangePasswordResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict]=None   
    
# get user profile

class GetUserProfileRequest(BaseModel):
    user_id: int
    
class GetUserProfileResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict]=None
    
# update user profile
class UpdateUserProfileRequest(BaseModel):
    user_id: int
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    
class UpdateUserProfileResponse(BaseModel):
    status: str
    message: str    
    data: Optional[Dict]=None   
    