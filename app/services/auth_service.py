from fastapi import HTTPException
from psycopg2.extras import DictCursor
from datetime import datetime, timezone, timedelta
from app.config import get_db_connection, conn, SECRECT_KEY, ALGORITHM, access_token, passkey, GMT_PLUS_7
from app.schemas.auth_schemas import RegisterRequest, RegisterResponse, TokenRequest, TokenResponse, ForgetPasswordRequest, ForgetPasswordResponse, ResetPasswordRequest, ResetPasswordResponse, LoginRequest, LoginResponse
from app.core.security import verify_password, validate_password_strength, get_password_hash, create_access_token, get_user_from_token, create_reset_token, verify_reset_token   
import requests
import jwt


# untuk daftar

def register_user_service(request):
    """
    Fungsi layanan untuk mendaftarkan pengguna baru dengan validasi dan langkah-langkah keamanan.
    
    Args:
        request: RegisterRequest yang berisi informasi pendaftaran pengguna
        
    Returns:
        Dictionary with registration status, message, and user data
        
    Raises:
        HTTPException: Jika pendaftaran gagal karena kesalahan validasi atau masalah server
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Validate username
            if not request.username or len(request.username) < 3:
                raise HTTPException(status_code=400, detail="Username must be at least 3 characters long.")
                
            # Check if username already exists
            cursor.execute("SELECT username FROM m_users WHERE username = %s", (request.username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                raise HTTPException(status_code=400, detail="Username already exists.")
            
            # Validate and check if email exists (if provided)
            if hasattr(request, 'email') and request.email:
                # Simple email validation
                if '@' not in request.email or '.' not in request.email:
                    raise HTTPException(status_code=400, detail="Please provide a valid email address.")
                    
                cursor.execute("SELECT email FROM m_users WHERE email = %s", (request.email,))
                existing_email = cursor.fetchone()
                
                if existing_email:
                    raise HTTPException(status_code=400, detail="Email already registered.")
            
            # Validate password strength
            validate_password_strength(request.password)
            
            # Generate password hash
            password_hash = get_password_hash(request.password)
            
            # Determine user_type default
            user_type = getattr(request, 'user_type', 'standard')
            
            current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            
            # Insert new user to database
            cursor.execute(
                """
                INSERT INTO m_users (
                    username, password_hash, email, user_type, 
                    full_name, created_at, updated_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING user_id
                """,
                (
                    request.username, 
                    password_hash, 
                    getattr(request, 'email', None),
                    user_type,
                    getattr(request, 'full_name', None),
                    current_time,
                    current_time,
                    'active'  # Default status
                )
            )
            
            # Get user_id from insert result
            user_id = cursor.fetchone()["user_id"]
            
            # Assign default role to user
            default_role_id = 1  # default role ID / admin
            cursor.execute(
                "INSERT INTO m_user_roles (user_id, roleid, created_at) VALUES (%s, %s, %s)",
                (user_id, default_role_id, current_time)
            )
            
            # Initialize login_attempts for new user
            cursor.execute(
                "INSERT INTO r_login_attempts (user_id, attempts, require_captcha, attempt_time) VALUES (%s, %s, %s, %s)",
                (user_id, 0, False, current_time)
            )
            
            # Generate JWT token for new user
            token_payload = {"sub": request.username, "user_id": user_id}
            access_token_generated = create_access_token(token_payload)
            
            # Decode token to get expire_time (for storing in database)
            decoded_token = jwt.decode(access_token_generated, options={"verify_signature": False})
            expire_time = datetime.fromtimestamp(decoded_token["exp"], tz=timezone.utc).astimezone(GMT_PLUS_7)
            
            # Commit all database changes
            conn.commit()
            
            # Save session token to database
            cursor.execute(
                "INSERT INTO r_sessions (user_id, jwt_token, expires_at) VALUES (%s, %s, %s)",
                (user_id, access_token_generated, expire_time)
            )
            conn.commit()
            
            # Return response with token
            return {
                "status": "success",
                "message": "Registration successful.",
                "data": {
                    "user_id": user_id,
                    "username": request.username,
                    "email": getattr(request, 'email', None),
                    "user_type": user_type,
                    "access_token": access_token_generated,
                    "token_type": "bearer"
                }
            }
                
    except HTTPException as e:
        conn.rollback()
        raise e
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        if conn is not None:
            conn.close()
              
# untuk login
def login_user_service(request):
    """
    Fungsi login yang mencakup validasi user, 
    pengecekan login attempts, validasi CAPTCHA (jika diperlukan),
    generate JWT dari service eksternal, serta memasukkan session ke database.
    """
    get_db_connection()
    global conn
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Fetch user based on username
            cursor.execute("SELECT * FROM m_users WHERE username = %s", (request.username,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid username or password.")

            # Fetch login attempts
            cursor.execute("SELECT * FROM r_login_attempts WHERE user_id = %s", (user["user_id"],))
            login_attempt = cursor.fetchone()

            current_time = datetime.now(GMT_PLUS_7)
            time_limit = current_time - timedelta(hours=24)

            if not login_attempt:
                cursor.execute(
                    "INSERT INTO r_login_attempts (user_id, attempts, require_captcha, attempt_time) VALUES (%s, %s, %s, %s)",
                    (user["user_id"], 0, False, current_time.strftime("%Y-%m-%d %H:%M:%S"))
                )
                conn.commit()
                # Create new dictionary for login_attempt
                login_attempt = {"attempts": 0, "require_captcha": False}
            else:
                # Fix: Handle the case where attempt_time is already a datetime object
                attempt_time = None
                if login_attempt["attempt_time"] is not None:
                    if isinstance(login_attempt["attempt_time"], str):
                        try:
                            attempt_time = datetime.strptime(login_attempt["attempt_time"], "%Y-%m-%d %H:%M:%S")
                            attempt_time = attempt_time.replace(tzinfo=GMT_PLUS_7)
                        except ValueError:
                            raise HTTPException(status_code=500, detail="Invalid attempt_time format in database.")
                    elif isinstance(login_attempt["attempt_time"], datetime):
                        # If it's already a datetime object, just add timezone info if needed
                        attempt_time = login_attempt["attempt_time"]
                        if attempt_time.tzinfo is None:
                            attempt_time = attempt_time.replace(tzinfo=GMT_PLUS_7)

                # Reset login attempt 
                if attempt_time and attempt_time < time_limit:
                    cursor.execute(
                        "UPDATE r_login_attempts SET attempts = 0, require_captcha = FALSE, attempt_time = %s WHERE user_id = %s",
                        (current_time.strftime("%Y-%m-%d %H:%M:%S"), user["user_id"])
                    )
                    conn.commit()
                    login_attempt["attempts"] = 0
                    login_attempt["require_captcha"] = False

            # Jika CAPTCHA diwajibkan
            if login_attempt["require_captcha"]:
                captcha_api_url = "https://recaptcha-api-209565413074.asia-southeast2.run.app/captcha"
                payload = {
                    "username": request.username,
                    "password": request.password,
                    "captcha_response": request.captcha_response,
                }
                captcha_response = requests.post(captcha_api_url, json=payload)
                if captcha_response.status_code == 401:
                    raise HTTPException(status_code=401, detail="CAPTCHA validated, but username or password is incorrect.")
                if captcha_response.status_code != 200:
                    raise HTTPException(status_code=400, detail="Captcha validation failed.")

            # Validasi password
            if not verify_password(request.password, user["password_hash"]):
                attempts = login_attempt["attempts"] + 1
                require_captcha = attempts > 3
                cursor.execute(
                    "UPDATE r_login_attempts SET attempts = %s, require_captcha = %s, attempt_time = %s WHERE user_id = %s",
                    (attempts, require_captcha, current_time.strftime("%Y-%m-%d %H:%M:%S"), user["user_id"])
                )
                conn.commit()
                if require_captcha:
                    raise HTTPException(status_code=400, detail="Captcha is required.")
                raise HTTPException(status_code=401, detail="Invalid username or password.")

            # Jika login berhasil, reset login_attempt
            cursor.execute(
                "UPDATE r_login_attempts SET attempts = 0, require_captcha = FALSE, attempt_time = %s WHERE user_id = %s",
                (current_time.strftime("%Y-%m-%d %H:%M:%S"), user["user_id"])
            )

            # Fetch entity terkait user (melalui role)
            cursor.execute(
                """
                SELECT DISTINCT d.entityid, e.entity_type, e.entity_name
                FROM (
                    SELECT a.roleid
                    FROM m_user_roles a
                    LEFT JOIN m_roles_component b ON a.roleid = b.roleid
                    WHERE a.user_id = %s AND b.accesslevel > 0
                ) AS t1
                LEFT JOIN m_role_id d ON d.roleid = t1.roleid
                LEFT JOIN m_entities e ON e.entity_id = d.entityid
                """,
                (user["user_id"],)
            )
            entities = cursor.fetchall()
            entity_result = [
                {"entityid": entity["entityid"], 
                 "entity_type": entity["entity_type"], 
                 "entity_name": entity["entity_name"]}
                for entity in entities
            ]
            
            # Generate JWT token menggunakan fungsi internal
            token_payload = {"sub": user["username"]}
            access_token_generated = create_access_token(token_payload)
            decoded_token = jwt.decode(access_token_generated, options={"verify_signature": False})
            expire_time = datetime.fromtimestamp(decoded_token["exp"], tz=timezone.utc).astimezone(GMT_PLUS_7)

            # Generate JWT token melalui service eksternal
            # headers = {"access_token": access_token}
            # token_payload = {
            #     "passkey": passkey,
            #     "username": user["username"]
            # }
            # token_response = requests.post(
            #     "https://get-jwt-token-209565413074.asia-southeast2.run.app/getToken",
            #     json=token_payload,
            #     headers=headers
            # )
            # if token_response.status_code != 200:
            #     raise HTTPException(status_code=500, detail="Failed to fetch token.")
            # token_data = token_response.json()
            # decoded_token = jwt.decode(token_data["access_token"], options={"verify_signature": False})
            # expire_time = datetime.fromtimestamp(decoded_token["exp"], tz=timezone.utc).astimezone(GMT_PLUS_7)

            # # Fetch role user melalui service eksternal
            # role_payload = {"userid": user["user_id"]}
            # user_role_response = requests.post(
            #     "https://get-user-role-209565413074.asia-southeast2.run.app/getUserRole",
            #     json=role_payload,
            #     headers={"access_token": token_data["access_token"]}
            # )
            # if user_role_response.status_code != 200:
            #     raise HTTPException(status_code=500, detail="Failed to fetch user role.")
            # role_data = user_role_response.json()
                        # Fetch role user secara internal (misalnya dari tabel m_user_roles dan m_roles)
            cursor.execute(
                """
                SELECT r.roleid, r.role_name
                FROM m_user_roles ur
                JOIN m_roles r ON ur.roleid = r.roleid
                WHERE ur.user_id = %s
                """,
                (user["user_id"],)
            )
            roles = cursor.fetchall()
            role_data = {"result": [{"roleid": role["roleid"], "role_name": role["role_name"]} for role in roles]}

            # Masukkan session ke database
            cursor.execute(
                "INSERT INTO r_sessions (user_id, jwt_token, expires_at) VALUES (%s, %s, %s)",
                (user["user_id"], access_token_generated, # token_data["access_token"],
                expire_time))
            conn.commit()

            # Kembalikan respon login
            return {
                "status": "success",
                "message": "Login successful.",
                "data": {
                    "access_token": access_token_generated,
                    "token_type": "bearer",
                    "user_type": user["user_type"],
                    "entity_result": entity_result,
                    "result": role_data["result"],
                }
            }
    finally:
        if conn is not None:
            conn.close()

# Fungsi untuk request forget password
def forget_password_service(request):
    """
    Fungsi untuk memproses permintaan lupa password.
    1. Validasi email/username ada di database
    2. Buat reset token
    3. Simpan token dan waktu permintaan ke database
    """
    get_db_connection()
    global conn
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Cari user berdasarkan email
            cursor.execute("SELECT user_id, username FROM m_users WHERE email = %s", (request.email,))
            user = cursor.fetchone()
            
            if not user:
                raise HTTPException(status_code=404, detail="Email not found.")
            
            user_id = user["user_id"]
            username = user["username"]
            
            # Generate reset token (berlaku 24 jam)
            reset_token = create_reset_token(
                {"sub": username, "email": request.email, "user_id": user_id},
                timedelta(hours=24)
            )
            
            current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            
            # Periksa apakah sudah ada permintaan reset sebelumnya
            cursor.execute(
                "SELECT id FROM r_password_resets WHERE user_id = %s", 
                (user_id,)
            )
            existing_request = cursor.fetchone()
            
            if existing_request:
                # Update permintaan yang sudah ada
                cursor.execute(
                    """
                    UPDATE r_password_resets 
                    SET reset_token = %s, created_at = %s, updated_at = %s, is_used = FALSE
                    WHERE user_id = %s
                    """,
                    (reset_token, current_time, current_time, user_id)
                )
            else:
                # Buat permintaan baru
                cursor.execute(
                    """
                    INSERT INTO r_password_resets 
                    (user_id, reset_token, created_at, updated_at, is_used)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user_id, reset_token, current_time, current_time, False)
                )
            
            conn.commit()
            
            # Di implementasi sesungguhnya, kirim email reset password ke user
            # dengan token atau link yang berisi token
            
            return {
                "status": "success",
                "message": "Password reset instructions sent to your email.",
                "data": {
                    "reset_token": reset_token  # contoh untuk dilihat di client
                }
            }
            
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process password reset request: {str(e)}")
    finally:
        if conn is not None:
            conn.close()

# Fungsi untuk reset password dengan token
def reset_password_service(request):
    """
    Fungsi untuk mereset password dengan token.
    1. Validasi token masih valid dan belum kadaluarsa
    2. Validasi password baru tidak sama dengan password lama
    3. Update password
    4. Tandai token sebagai sudah digunakan
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Verifikasi token
            payload = payload = verify_reset_token(request.token)
            if not payload:
                raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
            
            user_id = payload.get("user_id")
            email = payload.get("email")
            
            # Validasi token ada di database dan belum digunakan
            cursor.execute(
                """
                SELECT id, reset_token, created_at, is_used 
                FROM r_password_resets 
                WHERE user_id = %s AND reset_token = %s
                """, 
                (user_id, request.token)        # <— request.token
            )
            reset_request = cursor.fetchone()
            
            if not reset_request:
                raise HTTPException(status_code=400, detail="Invalid reset request.")
                
            if reset_request["is_used"]:
                raise HTTPException(status_code=400, detail="This reset token has already been used.")
                
            # Ambil informasi password lama
            cursor.execute(
                "SELECT password_hash FROM m_users WHERE user_id = %s", 
                (user_id,)
            )
            user_data = cursor.fetchone()
            
            if not user_data:
                raise HTTPException(status_code=404, detail="User not found.")
                
            # Validasi password baru tidak sama dengan yang lama
            if verify_password(request.new_password, user_data["password_hash"]):
                raise HTTPException(
                    status_code=400, 
                    detail="New password cannot be the same as the old password."
                )
                
            # Validasi format password (bisa disesuaikan)
            if len(request.new_password) < 8:
                raise HTTPException(
                    status_code=400, 
                    detail="Password must be at least 8 characters long."
                )
                
            # Konfirmasi password
            if request.new_password != request.confirm_password:
                raise HTTPException(
                    status_code=400, 
                    detail="Password confirmation does not match."
                )
                
            # Generate hash untuk password baru
            new_password_hash = get_password_hash(request.new_password)
            
            current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            
            # Update password user
            cursor.execute(
                """
                UPDATE m_users 
                SET password_hash = %s, updated_at = %s
                WHERE user_id = %s
                """,
                (new_password_hash, current_time, user_id)
            )
            
            # Tandai token sebagai sudah digunakan
            cursor.execute(
                """
                UPDATE r_password_resets 
                SET is_used = TRUE, updated_at = %s
                WHERE user_id = %s AND reset_token = %s
                """,
                (current_time, user_id, request.token)  # <— request.token
            )
            
            conn.commit()
            
            return {
                "status": "success",
                "message": "Password has been reset successfully.",
                "data": None
            }
            
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {e}")
    finally:
        if conn is not None:
            conn.close()
        
def change_password_service(request):
    """
    Fungsi untuk mengganti password pengguna.
    
    1. Verifikasi password lama
    2. Validasi password baru (kekuatan dan tidak sama dengan password lama)
    3. Update password di database
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Ambil password hash user
            cursor.execute(
                "SELECT password_hash FROM m_users WHERE user_id = %s", 
                (request.user_id,)
            )
            user_data = cursor.fetchone()
            
            if not user_data:
                raise HTTPException(status_code=404, detail="User not found.")
                
            # Verifikasi password lama
            if not verify_password(request.old_password, user_data["password_hash"]):
                raise HTTPException(status_code=400, detail="Current password is incorrect.")
                
            # Validasi password baru tidak sama dengan yang lama
            if verify_password(request.new_password, user_data["password_hash"]):
                raise HTTPException(
                    status_code=400, 
                    detail="New password cannot be the same as the current password."
                )
                
            # Validasi kekuatan password baru
            try:
                validate_password_strength(request.new_password)
            except HTTPException as e:
                # Jika validasi gagal, kembalikan error
                raise e
                
            # Konfirmasi password
            if request.new_password != request.confirm_password:
                raise HTTPException(
                    status_code=400, 
                    detail="Password confirmation does not match."
                )
            
            # Periksa apakah tabel password history ada
            history_table_exists = False
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'm_password_history'
                );
            """)
            history_table_exists = cursor.fetchone()[0]
            
            # Jika tabel password history ada, periksa riwayat password
            if history_table_exists:
                cursor.execute(
                    """
                    SELECT password_hash 
                    FROM m_password_history 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 5
                    """, 
                    (request.user_id,)
                )
                password_history = cursor.fetchall()
                
                # Periksa apakah password baru sama dengan salah satu dari 5 password terakhir
                for history_item in password_history:
                    if verify_password(request.new_password, history_item["password_hash"]):
                        raise HTTPException(
                            status_code=400, 
                            detail="Cannot reuse any of your last 5 passwords."
                        )
                
            # Generate hash untuk password baru
            new_password_hash = get_password_hash(request.new_password)
            
            current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            
            # Update password user
            cursor.execute(
                """
                UPDATE m_users 
                SET password_hash = %s, updated_at = %s
                WHERE user_id = %s
                """,
                (new_password_hash, current_time, request.user_id)
            )
            
            # Simpan password lama ke riwayat password jika tabel ada
            if history_table_exists:
                cursor.execute(
                    """
                    INSERT INTO m_password_history (user_id, password_hash, created_at)
                    VALUES (%s, %s, %s)
                    """,
                    (request.user_id, user_data["password_hash"], current_time)
                )
            
            conn.commit()
            
            return {
                "status": "success",
                "message": "Password has been changed successfully.",
                "data": None
            }
            
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=f"Failed to change password: {str(e)}")
    finally:
        if conn is not None:
            conn.close()   
       
def get_user_profile_service(request):
    """
    Service function untuk mendapatkan informasi profil pengguna.
    
    Args:
        user_id: ID pengguna yang memiliki informasi profil yang dikembalikan
        
    Returns:
        Dictionary dengan informasi profil pengguna
        
    Raises:
        HTTPException: Jika pengguna tidak ditemukan atau ada kesalahan lain
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Query to get user profile data
            cursor.execute(
                """
                SELECT 
                    user_id, username, email, user_type, full_name,  created_at, updated_at, status
                FROM 
                    m_users 
                WHERE 
                    user_id = %s
                """,
                (request.user_id,)
            )
            user_profile = cursor.fetchone()
            
            if not user_profile:
                raise HTTPException(status_code=404, detail="User not found.")
            
            # Convert to dict and remove sensitive data
            profile_data = dict(user_profile)
            
            # Get user roles
            cursor.execute(
                """
                SELECT r.roleid, r.role_name
                FROM m_user_roles ur
                JOIN m_roles r ON ur.roleid = r.roleid
                WHERE ur.user_id = %s
                """,
                (request.user_id,)
            )
            user_roles = cursor.fetchall()
            
            # Format timestamp fields for serialization
            for key in ['created_at', 'updated_at']:
                if profile_data[key] and isinstance(profile_data[key], datetime):
                    profile_data[key] = profile_data[key].strftime("%Y-%m-%d %H:%M:%S")
            
            # Add roles to profile data
            profile_data['roles'] = [{"roleid": role["roleid"], "role_name": role["role_name"]} 
                                     for role in user_roles]
            
            return {
                "status": "success",
                "message": "Profile retrieved successfully.",
                "data": profile_data
            }
                
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve user profile: {str(e)}")
    finally:
        if conn is not None:
            conn.close()
            
def update_user_profile_service(request):
    """
    Service function untuk memperbarui informasi profil pengguna.
    
    Args:
        user_id: ID pengguna yang memiliki informasi profil yang diupdate
        request: UpdateProfileRequest yang berisi informasi profil pengguna yang diupdate
        
    Returns:
        Dictionary dengan informasi profil pengguna yang diupdate
        
    Raises:
        HTTPException: Jika validasi gagal atau ada kesalahan lain
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # First check if user exists
            cursor.execute("SELECT username, email FROM m_users WHERE user_id = %s", (request.user_id,))
            existing_user = cursor.fetchone()
            
            if not existing_user:
                raise HTTPException(status_code=404, detail="User not found.")
            
            # Initialize update fields and values
            update_fields = []
            update_values = []
            
            # Handle email update if provided
            if hasattr(request, 'email') and request.email and request.email != existing_user["email"]:
                # Email validation
                if '@' not in request.email or '.' not in request.email:
                    raise HTTPException(status_code=400, detail="Please provide a valid email address.")
                
                # Check if new email already exists for another user
                cursor.execute("SELECT user_id FROM m_users WHERE email = %s AND user_id != %s", 
                              (request.email, request.user_id))
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Email already registered to another user.")
                
                update_fields.append("email = %s")
                update_values.append(request.email)
            
            # Handle full name update
            if hasattr(request, 'full_name') and request.full_name is not None:
                update_fields.append("full_name = %s")
                update_values.append(request.full_name)
              
            # If nothing to update, return early
            if not update_fields:
                return {
                    "status": "success",
                    "message": "No changes to update.",
                    "data": None
                }
            
            # Add updated_at timestamp
            current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            update_fields.append("updated_at = %s")
            update_values.append(current_time)
            
            # Add user_id to values for WHERE clause
            update_values.append(request.user_id)
            
            # Build and execute update query
            update_query = f"""
                UPDATE m_users 
                SET {', '.join(update_fields)}
                WHERE user_id = %s
                RETURNING user_id, username, email, full_name, updated_at
            """
            
            cursor.execute(update_query, update_values)
            updated_profile = cursor.fetchone()
            
            conn.commit()
            
            # Format timestamp for serialization
            if isinstance(updated_profile["updated_at"], datetime):
                updated_profile["updated_at"] = updated_profile["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
            
            return {
                "status": "success",
                "message": "Profile updated successfully.",
                "data": dict(updated_profile)
            }
                
    except HTTPException as e:
        conn.rollback()
        raise e
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update user profile: {str(e)}")
    finally:
        if conn is not None:
            conn.close()
       
# def register_user_service(request):
#     conn = get_db_connection()
#     try:
#         with conn.cursor(cursor_factory=DictCursor) as cursor:
#             # Periksa apakah username sudah ada
#             cursor.execute("SELECT username FROM m_users WHERE username = %s", (request.username,))
#             existing_user = cursor.fetchone()
            
#             if existing_user:
#                 raise HTTPException(status_code=400, detail="Username already exists.")
            
#             # Periksa apakah email sudah ada (jika ada validasi email)
#             if hasattr(request, 'email') and request.email:
#                 cursor.execute("SELECT email FROM m_users WHERE email = %s", (request.email,))
#                 existing_email = cursor.fetchone()
                
#                 if existing_email:
#                     raise HTTPException(status_code=400, detail="Email already registered.")
            
#             # Generate password hash
#             password_hash = get_password_hash(request.password)
            
#             # Tentukan user_type default (misalnya 'standard')
#             user_type = getattr(request, 'user_type', 'standard')
            
#             current_time = datetime.now(GMT_PLUS_7).strftime("%Y-%m-%d %H:%M:%S")
            
#             # Insert user baru ke database
#             cursor.execute(
#                 """
#                 INSERT INTO m_users (
#                     username, password_hash, email, user_type, 
#                     full_name, created_at, updated_at, status
#                 ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING user_id
#                 """,
#                 (
#                     request.username, 
#                     password_hash, 
#                     getattr(request, 'email', None),
#                     user_type,
#                     getattr(request, 'full_name', None),
#                     current_time,
#                     current_time,
#                     'active'  # Status default
#                 )
#             )
            
#             # Mendapatkan user_id dari hasil insert
#             user_id = cursor.fetchone()["user_id"]
            
#             # Berikan role default ke user
#             default_role_id = 1  # Sesuaikan dengan ID role default di sistem Anda
#             cursor.execute(
#                 "INSERT INTO m_user_roles (user_id, roleid, created_at) VALUES (%s, %s, %s)",
#                 (user_id, default_role_id, current_time)
#             )
            
#             # Inisialisasi login_attempts untuk user baru
#             cursor.execute(
#                 "INSERT INTO r_login_attempts (user_id, attempts, require_captcha, attempt_time) VALUES (%s, %s, %s, %s)",
#                 (user_id, 0, False, current_time)
#             )
#                         # Generate JWT token untuk user baru menggunakan fungsi internal
#             token_payload = {"sub": request.username}
#             access_token_generated = create_access_token(token_payload)
            
#             # Decode token untuk mendapatkan expire_time
#             decoded_token = jwt.decode(access_token_generated, options={"verify_signature": False})
#             expire_time = datetime.fromtimestamp(decoded_token["exp"], tz=timezone.utc).astimezone(GMT_PLUS_7)
            
#             # Commit semua perubahan database
#             conn.commit()
            
#             # Simpan session token ke database
#             cursor.execute(
#                 "INSERT INTO r_sessions (user_id, jwt_token, expires_at) VALUES (%s, %s, %s)",
#                 (user_id, access_token_generated, expire_time)
#             )
#             conn.commit()
            
#             # Kembalikan respons dengan token
#             return {
#                 "status": "success",
#                 "message": "Registration successful.",
#                 "data": {
#                     "user_id": user_id,
#                     "username": request.username,
#                     "access_token": access_token_generated,
#                     "token_type": "bearer"
#                 }
#             }
            
#             # # Generate JWT token untuk user baru (opsional)
#             # headers = {"access_token": access_token}
#             # token_payload = {
#             #     "passkey": passkey,
#             #     "username": request.username
#             # }
#             # token_response = requests.post(
#             #     "https://get-jwt-token-209565413074.asia-southeast2.run.app/getToken",
#             #     json=token_payload,
#             #     headers=headers
#             # )
            
#             # # Commit semua perubahan database
#             # conn.commit()
            
#             # # Jika token berhasil didapatkan, simpan ke session
#             # if token_response.status_code == 200:
#             #     token_data = token_response.json()
#             #     decoded_token = jwt.decode(token_data["access_token"], options={"verify_signature": False})
#             #     expire_time = datetime.fromtimestamp(decoded_token["exp"], tz=timezone.utc).astimezone(GMT_PLUS_7)
                
#             #     cursor.execute(
#             #         "INSERT INTO r_sessions (user_id, jwt_token, expires_at) VALUES (%s, %s, %s)",
#             #         (user_id, token_data["access_token"], expire_time)
#             #     )
#             #     conn.commit()
                
#             #     # Kembalikan respons dengan token
#             #     return {
#             #         "status": "success",
#             #         "message": "Registration successful.",
#             #         "data": {
#             #             "user_id": user_id,
#             #             "username": request.username,
#             #             "access_token": token_data["access_token"],
#             #             "token_type": token_data["token_type"]
#             #         }
#             #     }
#             # else:
#             #     # Kembalikan respons tanpa token
#             #     return {
#             #         "status": "success",
#             #         "message": "Registration successful. Please login to continue.",
#             #         "data": {
#             #             "user_id": user_id,
#             #             "username": request.username
#             #         }
#             #     }
                
#     except Exception as e:
#         conn.rollback()
#         raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
#     finally:
#         conn.close()
  