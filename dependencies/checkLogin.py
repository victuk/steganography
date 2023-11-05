from ast import Try
import jwt
from dotenv import dotenv_values
from fastapi import HTTPException, Header


env_vars = dotenv_values(".env")

def check(token: str = Header(...)):
    try:
         decoded = jwt.decode(token, env_vars["jwtSecret"], algorithms="HS256")
         return decoded
    except:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")