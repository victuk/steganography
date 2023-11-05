from utilities.db_handler import db
from fastapi import APIRouter, Header, HTTPException, Depends
from typing import Union
from base_models.models import ShowProfile
from dependencies.checkLogin import check


user_router = APIRouter()


@user_router.get(
    "/get-profile",
    response_description="Show the profile of the current user",
    response_model=ShowProfile
)
async def returns_the_current_users_profile(result = Depends(check)):
    try:
        req = await db["students"].find_one({"email": result['email']})

        return {'name': req['username'], 'email': req['email']}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Internal server error")
