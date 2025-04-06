import secrets


SECRET_KEY = secrets.token_hex(32)
passkey = secrets.token_hex(32)
access_token = secrets.token_hex(32)

print("SECRET_KEY:", SECRET_KEY)
print("passkey:", passkey)
print("access_token:", access_token)
