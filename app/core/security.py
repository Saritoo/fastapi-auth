from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException
from app.config import SECRECT_KEY, ALGORITHM
from app.config import GMT_PLUS_7

# Setup password context untuk hashing dan verifikasi password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """
    Menghasilkan hash dari password plaintext.
    
    Args:
        password: String plaintext password
        
    Returns:
        String hash password yang dienkripsi
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Memverifikasi apakah password plaintext cocok dengan hash.
    
    Args:
        plain_password: String plaintext password untuk diverifikasi
        hashed_password: String hash password yang tersimpan
        
    Returns:
        Boolean yang menunjukkan apakah password valid
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Membuat JWT access token.
    
    Args:
        data: Dictionary data yang akan dienkode dalam token
        expires_delta: Optional timedelta yang menentukan masa aktif token
        
    Returns:
        String JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(GMT_PLUS_7) + expires_delta
    else:
        expire = datetime.now(GMT_PLUS_7) + timedelta(minutes=30)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRECT_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    """
    Mendekode dan memverifikasi JWT token.
    
    Args:
        token: String JWT token untuk didekode
        
    Returns:
        Dictionary payload dari token jika valid
        
    Raises:
        HTTPException: Jika token tidak valid atau expired
    """
    try:
        payload = jwt.decode(token, SECRECT_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_user_from_token(token: str) -> dict:
    """
    Mendapatkan informasi user dari JWT token.
    
    Args:
        token: String JWT token
        
    Returns:
        Dictionary berisi informasi user dari token payload
        
    Raises:
        HTTPException: Jika token tidak valid
    """
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    return {
        "username": payload.get("sub"),
        "exp": payload.get("exp")
    }

def validate_password_strength(password: str) -> bool:
    """
    Validasi kekuatan password.
    
    Args:
        password: String password yang akan divalidasi
        
    Returns:
        Boolean yang menunjukkan apakah password memenuhi persyaratan
        
    Raises:
        HTTPException: Jika password tidak memenuhi persyaratan
    """
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    
    # Tambahkan validasi lain sesuai kebutuhan (karakter khusus, angka, dll)
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    
    if not (has_digit and has_upper and has_lower):
        raise HTTPException(
            status_code=400, 
            detail="Password must contain at least one digit, one uppercase and one lowercase letter"
        )
    
    return True

def rate_limit_check(attempts: int, max_attempts: int = 5, lockout_minutes: int = 30) -> bool:
    """
    Memeriksa apakah upaya login melebihi batas rate limit.
    
    Args:
        attempts: Jumlah percobaan login yang gagal
        max_attempts: Jumlah maksimum percobaan sebelum lockout
        lockout_minutes: Durasi lockout dalam menit
        
    Returns:
        Boolean yang menunjukkan apakah user terkunci
        
    Raises:
        HTTPException: Jika user terkunci karena terlalu banyak percobaan gagal
    """
    if attempts >= max_attempts:
        raise HTTPException(
            status_code=429, 
            detail=f"Too many failed attempts. Account locked for {lockout_minutes} minutes"
        )
    
    return False


# Fungsi untuk menghasilkan reset token
def create_reset_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(GMT_PLUS_7) + expires_delta
    else:
        # Default: token berlaku selama 24 jam
        expire = datetime.now(GMT_PLUS_7) + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRECT_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Fungsi untuk memverifikasi token
def verify_reset_token(token: str):
    try:
        payload = jwt.decode(token, SECRECT_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None