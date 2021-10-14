import os

from fastapi import status, HTTPException
from dotenv import dotenv_values


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config = dotenv_values(os.path.join(BASE_DIR, '.env'))

AUTH_EXCEPTION = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials, please try again", headers={"WWW-Authenticate": "Bearer"})