import secrets

# Generate a secure random secret key
jwt_secret_key = secrets.token_hex(32)
print(f"Your JWT Secret Key: {jwt_secret_key}")
