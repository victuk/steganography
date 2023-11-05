from ast import Try
import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, Header
import os

load_dotenv()

def check(token: str = Header(...)):
    try:
         decoded = jwt.decode(token, os.getenv("jwtSecret"), algorithms="HS256")
         return decoded
    except:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")