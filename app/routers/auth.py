from fastapi import APIRouter, Depends, HTTPException
from app.schemas.auth_schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse, ForgetPasswordRequest, ForgetPasswordResponse, ResetPasswordRequest, ResetPasswordResponse, ChangePasswordRequest, ChangePasswordResponse, GetUserProfileRequest, GetUserProfileResponse, UpdateUserProfileRequest, UpdateUserProfileResponse
from app.services.auth_service import forget_password_service, reset_password_service, login_user_service, register_user_service, change_password_service, get_user_profile_service, update_user_profile_service
router = APIRouter(prefix="/auth", tags=["Authentication"])


    
@router.post("/register", response_model=RegisterResponse)
async def register_user(request: RegisterRequest):
    """
    Endpoint untuk mendaftarkan pengguna baru.
    
    Parameters:
    - username: Username unik untuk pengguna
    - password: Password pengguna (min. 8 karakter)
    - email: Alamat email valid
    - full_name: Nama lengkap pengguna (opsional)
    - user_type: Tipe pengguna (default: standard)
    
    Returns:
    - Status pendaftaran
    - Data pengguna dan token (jika berhasil)
    """
    try:
        result = register_user_service(request)
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@router.post("/login", response_model=LoginResponse)
async def login_user(request: LoginRequest):
    """
    Endpoint untuk login pengguna.
    
    Parameters:
    - username: Username pengguna
    - password: Password pengguna
    - captcha_response: Captcha yang dikirim melalui email
    
    Returns:
    - Status login
    - Data pengguna dan token (jika berhasil)
    """
    try:
        result = login_user_service(request)
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@router.post("/forget-password", response_model=ForgetPasswordResponse)
async def forget_password(request: ForgetPasswordRequest):
    """
    API untuk meminta reset password.
    
    - **email**: Email pengguna yang terdaftar
    """
    return forget_password_service(request)

@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(request: ResetPasswordRequest):
    """
    API untuk mereset password dengan token.
    
    - **reset_token**: Token yang dikirim melalui email
    - **new_password**: Password baru
    - **confirm_password**: Konfirmasi password baru
    """
    return reset_password_service(request)

@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(request: ChangePasswordRequest):
    """
    API untuk mengubah password user yang sudah terotentikasi.
    
    - **user_id**: ID user yang akan diubah password
    - **old_password**: Password lama
    - **new_password**: Password baru
    - **confirm_password**: Konfirmasi password baru
    """
    return change_password_service(request) 

@router.post("/profile-inquiry", response_model=GetUserProfileResponse)
async def get_user_profile(request: GetUserProfileRequest):
    """
    API untuk mendapatkan informasi profil user.
    - **user_id**: ID user yang akan diketahui
    """
    return get_user_profile_service(request)

@router.post("/profile-update", response_model=UpdateUserProfileResponse)
async def update_user_profile(request: UpdateUserProfileRequest):
    """
    API untuk memperbarui informasi profil user.
    
    - **user_id**: ID user yang akan diubah
    - **email**: Alamat email baru (opsional)
    - **full_name**: Nama lengkap baru (opsional)
    """
    return update_user_profile_service(request) 