from decouple import config, RepositoryEnv, Config
import psycopg2
from fastapi import HTTPException
from datetime import timezone, timedelta

# Project info
PROJECT_NAME = "Authentication API"
VERSION = "1.0.0"
API_PREFIX = "/api/v1"

# mengambil config dari file .env
DOTENV_FILE = './.env'
env_config = Config(RepositoryEnv(DOTENV_FILE))

# konfigurasi database
host = env_config('DB_IP')
port = int(env_config('DB_PORT'))
user = env_config('DB_USR')
password = env_config('DB_PWD')
database = env_config('DB_NM')

conn = psycopg2.connect(
    dbname=database,
    user=user,
    password=password,
    host=host,
    port=port
)

# konfigurasi 
SECRECT_KEY = env_config('SECRET_KEY')
ALGORITHM = env_config('ALGORITHM')
access_token = env_config('access_token')
passkey = env_config('passkey')
GMT_PLUS_7 = timezone(timedelta(hours=7))

# konek ke database
def get_db_connection():
    global conn
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:
        try:
            conn = psycopg2.connect(
                host=host, 
                port=port, 
                user=user, 
                password=password, 
                dbname=database,
                sslmode='verify-ca'
            )
        except Exception as e:
            # Add return statement to stop execution if connection fails
            raise HTTPException(status_code=500, detail="Failed to connect to the database")
    
    # Only return conn if we reach this point
    return conn     