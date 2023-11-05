from fastapi import APIRouter, Depends, Header, HTTPException, Body, status
from fastapi.encoders import jsonable_encoder
from base_models.models import StudentModel, StudentModelReply, LoginModel, ShowSuccess
from fastapi.responses import JSONResponse
from utilities.passwordUtil import hash_password, verify_password
from dotenv import dotenv_values
from utilities.db_handler import db
import jwt
from typing import Union
import cryptocode
from utilities.sendEmail import sendHTML
from utilities import passwordUtil


authentication_router = APIRouter()
env_vars = dotenv_values(".env")


@authentication_router.post(
    "/register",
    response_description="Add new user to the database",
    description="Creates an account for the user",
    response_model=StudentModel)
async def creates_user_account(student: StudentModel = Body(...)):
    student = jsonable_encoder(student)
    studentS = await db["students"].find_one({"email": student["email"]})
    if studentS is not None:
        raise HTTPException(status_code=400, detail=f"Record already exists")
    else:
        student["password"] = hash_password(student["password"])
        new_student = await db["students"].insert_one(student)
        created_student = await db["students"].find_one({"_id": new_student.inserted_id})
        print(new_student.inserted_id)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={'created_student':{'_id':created_student['_id'],'email': created_student['email'], 'username': created_student['username']}, 'status': 'successful'})
        

@authentication_router.post(
        "/login",
        response_description="Logs the user in",
        response_model=StudentModelReply)
async def logs_in_the_user(student: LoginModel = Body(...)):
    student = jsonable_encoder(student)
    studentD = await db["students"].find_one({"email": student['email']})
    print(studentD)
    if studentD is not None:
        passwordMatch = verify_password(student['password'], studentD['password'])
        if passwordMatch == True:
            print('Passwords match')
            token = jwt.encode({'studentID':studentD['_id'], 'email':studentD['email']}, env_vars["jwtSecret"], algorithm="HS256")
            print(token.decode())
            return {'_id': studentD['_id'], 'username': studentD['username'], 'email': studentD['email'], 'token':token.decode()}
        else:
            raise HTTPException(status_code=404, detail=f"Login details not correct")
    else:
            raise HTTPException(status_code=404, detail=f"Student not found")




@authentication_router.post(
    "/forgot-password",
    response_description="Used to send an email to the user that wishes to reset his password",
    response_model=ShowSuccess
)
async def sends_a_forgot_password_email(email: Union[str, None] = Header(default=None)):

    studentS = await db["students"].find_one({"email": email})

    if studentS is not None:

        encode = cryptocode.encrypt(email, env_vars["jwtSecret"])

        message = 'Kindly click this button to reset your password: <div><a href="https://infocryptpro.netlify.app/reset-password.html?key=' + encode + '" target="_blank">Reset Button</a></div><br> \
        <div>You can use this link if the button is not working: https://infocryptpro.netlify.app/reset-password?key=' + encode + '</div>'

        sendHTML(email, email, 'Password reset', message)

        return {"status": "successful"}
    else:
        raise HTTPException(status_code=404, detail=f"Email not found")


@authentication_router.post(
    "/reset-password",
    response_description="Sets a new password for the user that made a request to reset his/her password",
    response_model=ShowSuccess
)
def resets_the_users_password(newPassword: Union[str, None] = Header(default=None), key: Union[str, None] = Header(default=None)):
    email = cryptocode.decrypt(key, env_vars["jwtSecret"])

    newPassword = passwordUtil.hash_password(newPassword)

    db["students"].update_one({"email": email}, {"$set": {'password': newPassword}})

    return {'status': 'successful'}



