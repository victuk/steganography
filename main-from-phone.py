from ast import Not
from email import message
import json
import os
import datetime
import resource
from fastapi import FastAPI, Body, HTTPException, status, Header, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from numpy import result_type
from models import Check, ImageFileResponse, StudentModel, Req, ShowProfile, responseWithPrivateKey, StudentModelReply, UpdateStudentModel, responseWithKey, LoginModel, Encrypt, EncryptedText, DecryptedText, Decrypt, ImageFile, HideText, ImageLink, ShowSuccess
from typing import List, Union
import motor.motor_asyncio
from pymongo import MongoClient
import hashPassword
import jwt
from PIL import Image
import requests
import rsa
import base64
from sendEmail import sendHTML, sendMail, sendMailTwo, sendMailWithAttachment, sendMailWithFile
from checkLogin import check
from main import encode_enc, modPix
from fastapi.middleware.cors import CORSMiddleware
from sys import stdout
from hideImageInImage import merge, unmerge
from fastapi.staticfiles import StaticFiles
import cloudinary
import cloudinary.uploader
import cloudinary.api
from customconfig import mongUrl, jwtSecret, cloudinary_api_secret, cloudinary_api_key, cloudinary_api_name
import cryptocode

# mongodb+srv://victor:<password>@cluster0.vrsrb.mongodb.net/
# os.environ["MONGODB_URL"]

app = FastAPI()

cloudinary.config( 
  cloud_name = cloudinary_api_name, 
  api_key = cloudinary_api_key, 
  api_secret = cloudinary_api_secret,
  secure = True
)

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

app.mount("/static", StaticFiles(directory="static"), name="static")

client = motor.motor_asyncio.AsyncIOMotorClient(mongUrl)
db = client.steg





@app.post("/register", response_description="Add new student", response_model=StudentModel)
async def create_student(student: StudentModel = Body(...)):
    student = jsonable_encoder(student)
    studentS = await db["students"].find_one({"email": student["email"]})
    if studentS is not None:
        raise HTTPException(status_code=404, detail=f"Record already exists")
    else:
        student["password"] = hashPassword.hash_password(student["password"])
        new_student = await db["students"].insert_one(student)
        created_student = await db["students"].find_one({"_id": new_student.inserted_id})
        print(new_student.inserted_id)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={'created_student':{'_id':created_student['_id'],'email': created_student['email'], 'username': created_student['username']}, 'status': 'successful'})
        

@app.post("/login", response_description="Logs In new student", response_model=StudentModelReply)
async def create_student(student: LoginModel = Body(...)):
    student = jsonable_encoder(student)
    studentD = await db["students"].find_one({"email": student['email']})
    print(studentD)
    if studentD is not None:
        passwordMatch = hashPassword.verify_password(student['password'], studentD['password'])
        if passwordMatch == True:
            print('Passwords match')
            token = jwt.encode({'studentID':studentD['_id'], 'email':studentD['email']}, jwtSecret, algorithm="HS256")
            print(token.decode())
            return {'_id': studentD['_id'], 'username': studentD['username'], 'email': studentD['email'], 'token':token.decode()}
        else:
            raise HTTPException(status_code=404, detail=f"Login details not correct")
    else:
            raise HTTPException(status_code=404, detail=f"Student not found")
    # student = jsonable_encoder(student)
    # student["password"] = hashPassword.hash_password(student["password"])
    # new_student = await db["students"].insert_one(student)
    # created_student = await db["students"].find_one({"_id": new_student.inserted_id})
    # return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_student)



# https://fastapi.tiangolo.com/tutorial/


@app.post(
    "/request-key", response_description="Get a single student", response_model=ShowSuccess
)
async def show_student(token: Union[str, None] = Header(default=None), requestEmail: Union[str, None] = Header(default=None)):
    result = check(token)
    if result is not None:
        db["requests"].insert_one({
            'sendersEmail': result['email'],
            'receiversEmail': requestEmail,
            'requestStatus': 'pending',
            'privateKeyLink': '',
            "date": datetime.datetime.now()
        })
        return {'status': 'Request Sent successfully'}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")

@app.get(
    "/key-request-status", response_description="Get a single student", response_model=ShowSuccess
)
async def show_student(token: Union[str, None] = Header(default=None), requestEmail: Union[str, None] = Header(default=None)):
    result = check(token)
    if result is not None:

        reqs = []

        req = db["pkLinks"].find({"sendersEmail": result['email']}).sort('i')
        for document in await req.to_list(length=100):
                    reqs.append(document)

        return {'reqStatus': req}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")

@app.post(
    "/approve-send-keys", response_description="Get a single student", response_model=responseWithPrivateKey
)
async def show_student(token: Union[str, None] = Header(default=None), approvalStatus: Union[str, None] = Header(default=None), keyL: Union[str, None] = Header(default=None)):
    result = check(token)
    if result is not None:
        r = await db["requests"].find_one({'receiversEmail': token['email']})

        if(keyL >= 1024):
            (publicKey, privateKey) = rsa.newkeys(keyL)

            with open('static/publicKey.pem', 'wb') as p:
                p.write(publicKey.save_pkcs1('PEM'))
            with open('static/privateKey.pem', 'wb') as p:
                p.write(privateKey.save_pkcs1('PEM'))

            with open('static/privateKey.pem', 'rb') as privatefile:
                privateKeydata = privatefile.read()

            with open('static/publicKey.pem', 'rb') as publicfile:
                publicKeydata = publicfile.read()

            # publicKeyMessage = 'Public Key to decrypt messages'

            # privateKeyMessage = 'Private Key to encrypt messages'

            # print('Sender', payload['email'])
            # print('Receiver', keyLength['PKReceiversEmail'])

            # sendMailWithFile(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, 'Private Key File', 'static/privateKey.pem')

            pk_response = cloudinary.uploader.upload("static/publicKey.pem", resource_type="raw")

            print(pk_response['secure_url'])
            print(pk_response['public_id'])

            # db["requests"].insert_one({
            #     'email': keyLength['PKReceiversEmail'],
            #     'sendersEmail': result['email'],
            #     'pkLink': pk_response['secure_url'],
            #     'pkPublicId': pk_response['public_id']
            # })

            db["requests"].update_one({"receiversEmail": result['email']}, {"$set": {'requestStatus': 'approved', 'publicKeyLink': pk_response['secure_url']}})

            # sendMailWithFile(payload['email'], payload['email'], publicKeyMessage, 'Public Key File', 'static/publicKey.pem')
            
            # sendMail(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, str(privateKeydata)[2:-1])

            # sendMail(payload['email'], payload['email'], publicKeyMessage, str(publicKeydata)[2:-1])
            return {'successful': True, 'privateKey': 'static/privateKey.pem'}

        else:
            print("Key length should not be less than 1024")
            raise HTTPException(status_code=404, detail=f"Key length should not be less than 1024")


        
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")



# https://fastapi.tiangolo.com/tutorial/

@app.get(
    "/get-profile", response_description="Get a single student", response_model=ShowProfile
)
async def show_student(token: Union[str, None] = Header(default=None)):
    result = check(token)
    if result is not None:

        req = await db["students"].find_one({"email": result['email']})

        print(req)

        return {'name': req['username'], 'email': req['email']}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")


@app.post(
    "/generate-key", response_description="List all students", response_model=responseWithKey
)
async def generate_keys(token: Union[str, None] = Header(default=None), keyLength: Req = Body(...)):
    print(token)
    keyLength = jsonable_encoder(keyLength)
    payload = jwt.decode(token, jwtSecret, algorithms="HS256")
    print(payload)
    print(keyLength)
    keyL = int(keyLength['keyLength'])
    result = check(token)
    if(keyL >= 1024):
        (publicKey, privateKey) = rsa.newkeys(keyL)

        with open('static/publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('static/privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))

        with open('static/privateKey.pem', 'rb') as privatefile:
            privateKeydata = privatefile.read()

        with open('static/publicKey.pem', 'rb') as publicfile:
            publicKeydata = publicfile.read()

        studentD = await db["students"].find_one({"email": payload['email']})
        user = await db["students"].find_one({"email": keyLength['PKReceiversEmail']})

        publicKeyMessage = '{} has sent you a public Key for message encryption.'.format(studentD['username'])

        privateKeyMessage = 'You have sent a public key to {}. Here is your private Key to decrypt messages'.format(user['username'])

        print('Sender', payload['email'])
        print('Receiver', keyLength['PKReceiversEmail'])

        sendMailWithFile(payload['email'], keyLength['PKReceiversEmail'], 'Public Key File', publicKeyMessage, 'static/publicKey.pem')

        pk_response = cloudinary.uploader.upload("static/publicKey.pem", resource_type="raw")

        print(pk_response['secure_url'])
        print(pk_response['public_id'])

        db["pkLinks"].insert_one({
            'email': keyLength['PKReceiversEmail'],
            'sendersEmail': result['email'],
            'pkLink': pk_response['secure_url'],
            'pkPublicId': pk_response['public_id'],
            "date": datetime.datetime.now()
        })

        sendMailWithFile(payload['email'], payload['email'], 'Private Key File', privateKeyMessage, 'static/privateKey.pem')
        
        # sendMail(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, str(privateKeydata)[2:-1])

        # sendMail(payload['email'], payload['email'], publicKeyMessage, str(publicKeydata)[2:-1])
        return {'successful': True, 'publicKey': 'static/publicKey.pem', 'privateKey': 'static/privateKey.pem'}

    else:
        print("Key length should not be less than 1024")
        raise HTTPException(status_code=404, detail=f"Key length should not be less than 1024")
    


@app.post(
    "/encrypt-text", response_description="Encrypts text", response_model=EncryptedText
)
async def list_students(text: Union[str, None] = Header(default=None), token: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    # payload = jwt.decode(token, jwtSecret, algorithms="HS256")
    # print(payload) .decode('utf-8')
    result = check(token)
    if result is not None:
        # enc = jsonable_encoder(enc)
        # print(enc)
        # encryptionKey = json.loads(encryptionKey)
        # base64.urlsafe_b64encode(enc['encryptionKey']).decode('utf-8')
        # with open(file., 'rb') as publicfile:
        #     publicKeydata = publicfile.read()
        
        content = file.file.read()


        with open(file.filename, 'wb') as f:
                f.write(content)

        # print(publicKeydata)

        with open(file.filename, 'rb') as publicfile:
            publicKeydata = publicfile.read()

        # return {'ciphertext': 'hhhhh'}
        # encryptionKey = encryptionKey.replace('\\n', '\n').replace('\\t', '\t')
        # print(text)
        publicKey = rsa.PublicKey.load_pkcs1(publicKeydata)
        encD = rsa.encrypt(text.encode('utf-8'), publicKey)
        encDToString = base64.urlsafe_b64encode(encD).decode('utf-8')
        
        return {'ciphertext': encDToString}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")


@app.post(
    "/decrypt-text", response_description="Decrypts text", response_model=DecryptedText
)
async def decrypt(ciphertext: Union[str, None] = Header(default=None), token: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    # payload = jwt.decode(token, jwtSecret, algorithms="HS256")
    # print(payload).decode('utf-8')
    
    result = check(token)
    if result is not None:
        # decryptionKey = jsonable_encoder(decryptionKey)
        # enn = json.dumps(enn)
        # enn = enn.json()

        content = file.file.read()

        # return {'plaintext': 'Hello'}


        with open(file.filename, 'wb') as f:
                f.write(content)

        with open(file.filename, 'rb') as privatefile:
            privateKeydata = privatefile.read()

        

        # decryptionKeyD = json.loads(json.dumps(decryptionKey))
        # pk = rsa.PrivateKey._load_pkcs1_pem

        # key = enn['decryptionKey']
        # decryptionKey = decryptionKey.replace('\\n', '\n').replace('\\t', '\t')

        # print(ciphertext)
        # print(decryptionKey)

        

        privateKey = rsa.PrivateKey.load_pkcs1(privateKeydata)

        # return {'plaintext': 'Hello'}
        # return {'plaintext': 'Hello'}
        binText = base64.urlsafe_b64decode(ciphertext)
        decodedVal = rsa.decrypt(binText, privateKey)
        decodedString = decodedVal.decode('utf-8')
        return {'plaintext': decodedString}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")


@app.post(
    "/hide-text-in-image", response_description="Hide a text in an image", response_model=ImageFile
)
async def list_students(token: Union[str, None] = Header(default=None), f5key: Union[str, None] = Header(default=None), textToHide: Union[str, None] = Header(default=None), email: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    # image = file.filename
    # fileAction = jsonable_encoder(file.action)
    result = check(token)
    if result is not None:
        
        try:
            contents = await file.read()
            with open(file.filename, 'wb') as f:
                f.write(contents)
        except Exception:
            return {"message": "There was an error uploading the file"}
        finally:
            await file.close()
            studentD = await db["students"].find_one({"email": email})
            user = await db["students"].find_one({"email": result['email']})
            
            if len(f5key) > 24 or len(f5key) < 6:
                raise HTTPException(status_code=404, detail=f"Invalid f5 key length")
            else:
                fileName = email[:-4]
                with open(fileName + '.txt', 'w') as f:
                    f.write(f5key)

            f5key = f5key.split(',')

            subject = "Email With Picture Attachment"
            message = "Hi {}, you have received an attachment from {}. Your f5 key is: {}".format(studentD['username'], user['username'], str(','.join(f5key)))
            messageTwo = "Hi {}, you sent an attachment to {} your f5 key is: {}".format(user['username'], email, str(','.join(f5key)))
            image = Image.open('./' + file.filename, 'r')
            newimg = image.copy()
            encode_enc(newimg, textToHide)
            new_img_name = 'imageWithHiddenText.png'
            newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

            pk_response = cloudinary.uploader.upload(new_img_name)

            print(pk_response['secure_url'])
            print(pk_response['public_id'])

            db["imageLinks"].insert_one({
                'email': email,
                'sendersEmail': result['email'],
                'pkLink': pk_response['secure_url'],
                'pkPublicId': pk_response['public_id'],
                "date": datetime.datetime.now()
            })

            pk_response_two = cloudinary.uploader.upload(fileName + '.txt', resource_type="raw")

            print(pk_response_two['secure_url'])
            print(pk_response_two['public_id'])

            db["fFiveLinks"].insert_one({
                'email': email,
                'sendersEmail': result['email'],
                'pkLink': pk_response_two['secure_url'],
                'pkPublicId': pk_response_two['public_id'],
                "date": datetime.datetime.now()
            })

            sendMailTwo(result['email'], result['email'], 'Your f5 key', messageTwo)
            sendMailWithAttachment(result['email'], email, subject, message, new_img_name)

        return {'status': 'Successful'}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")

@app.post(
    "/seperate-image", response_description="List all students", response_model=ImageFileResponse
)
async def list_students(token: Union[str, None] = Header(default=None), f5key: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    result = check(token)
    if result is not None:
        fileName = result['email'][:-4]
        key = open(fileName + '.txt', 'r')
        readKey = key.read()
        # print(readKey)
        # print(f5key)

        content = file.file.read()

        print(content)

        with open(file.filename, 'wb') as f:
                f.write(content)
        
        if readKey == f5key:

            image = Image.open(file.filename, 'r')
            data = ''
            imgdata = iter(image.getdata())


            while (True):
                pixels = [value for value in imgdata.__next__()[:3] +
                                        imgdata.__next__()[:3] +
                                        imgdata.__next__()[:3]]

                # string of binary data
                binstr = ''
        
                for i in pixels[:8]:
                    if (i % 2 == 0):
                        binstr += '0'
                    else:
                        binstr += '1'
                
                data += chr(int(binstr, 2))
                if (pixels[-1] % 2 != 0):
                    print(data)
                    return {'ciphertext': data}

        else:
            raise HTTPException(status_code=404, detail=f"f5 keys don't match")
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")  


@app.post(
    "/hide-image-in-image", response_description="Hides a smaller image in a larger image", response_model=ImageLink
)
async def show_student(token: Union[str, None] = Header(default=None), f5key: Union[str, None] = Header(default=None), email: Union[str, None] = Header(default=None),  file: UploadFile = File(...), fileTwo: UploadFile = File(...)):
    result = check(token)
    print(f5key)
    if result is not None:
        try:
            contents = await file.read()
            with open(file.filename, 'wb') as f:
                f.write(contents)

            contentsTwo = await fileTwo.read()
            with open(fileTwo.filename, 'wb') as f:
                f.write(contentsTwo)

        except Exception:
            return{"message": "can't get images"}
        finally:
            if len(f5key) > 24 or len(f5key) < 6:
                raise HTTPException(status_code=404, detail=f"Invalid f5 key length")
            else:
                fileName = result['email'][:-4]
                with open(fileName + 'forImg' + '.txt', 'w') as f:
                    f.write(f5key)

            f5key = f5key.split(',')

            studentD = await db["students"].find_one({"email": email})

            subject = "Email With Picture Attachment"
            message = "Hi {}, you have received an attachment. Your f5 key is: ".format(studentD['username'])

            # mcsteelandwoods.com

            merged_image = merge(Image.open(file.filename), Image.open(fileTwo.filename))
            merged_image.save('static/outputfile.png')
            sendMailWithAttachment(result['email'], email, subject, message + str(f5key), 'static/outputfile.png')
            return {"imageLink": "static/outputfile.png"}
            # merge(file.filename, fileTwo.filename, 'outputfile.png')
        
    # if (student := await db["students"].find_one({"_id": id})) is not None:
    #     return student
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")  


@app.post(
    "/reveal-hidden-image", response_description="Get a single student", response_model=ImageLink
)
async def show_student(token: Union[str, None] = Header(default=None), f5key: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    result = check(token)
    if result is not None:
        fileName = result['email'][:-4]
        key = open(fileName + 'forImg' + '.txt', 'r')
        readKey = key.read()

        print(key)
        print(readKey)
        print(f5key)

        if readKey == f5key:
            try:
                contents = await file.read()
                with open(file.filename, 'wb') as f:
                    f.write(contents)
            except Exception:
                return{"message": "can't get images"}
            finally:
                unmerged_image = unmerge(Image.open(file.filename))
                unmerged_image.save('static/the-hidden-image.png')
                return {"imageLink": "static/the-hidden-image.png"} 
    else:
        raise HTTPException(status_code=404, detail=f"Invalid token")  

@app.get(
    "/check-for-new", response_description="Get a single student", response_model=Check
)
async def show_student(token: Union[str, None] = Header(default=None)):
    result = check(token)
    if result is not None:

        
        # pkLinks imageLinks fFiveLinks
        private_key_links = db["pkLinks"].find({"email": result['email']}).sort('i')
        image_links = db["imageLinks"].find({"email": result['email']}).sort('i')
        f_five_links = db["fFiveLinks"].find({"email": result['email']}).sort('i')

        p_k_links = []
        i_links = []
        f_f_links = []

        for document in await private_key_links.to_list(length=100):
            p_k_links.append(document)

        for document in await image_links.to_list(length=100):
            i_links.append(document)

        for document in await f_five_links.to_list(length=100):
            f_f_links.append(document)

        # print(private_key_links)

        return {"private_key_links": p_k_links, "image_links": i_links, 'f_five_links': f_f_links}
    else:
        raise HTTPException(status_code=404, detail=f"Student {id} not found")

@app.post(
    "/forgot-password", response_description="Get a single student", response_model=ShowSuccess
)
async def show_student(email: Union[str, None] = Header(default=None)):

    studentS = await db["students"].find_one({"email": email})

    if studentS is not None:

        encode = cryptocode.encrypt(email, jwtSecret)

        message = 'Kindly click this button to reset your password: <div><a href="https://infocryptpro.netlify.app/reset-password.html?key=' + encode + '" target="_blank">Reset Button</a></div><br> \
        <div>You can use this link if the button is not working: https://infocryptpro.netlify.app/reset-password?key=' + encode + '</div>'

        sendHTML(email, email, 'Password reset', message)

        return {"status": "successful"}
    else:
        raise HTTPException(status_code=404, detail=f"Email not found")


@app.post(
    "/reset-password", response_description="Get a single student", response_model=ShowSuccess
)
def show_student(newPassword: Union[str, None] = Header(default=None), key: Union[str, None] = Header(default=None)):
    email = cryptocode.decrypt(key, jwtSecret)

    newPassword = hashPassword.hash_password(newPassword)

    db["students"].update_one({"email": email}, {"$set": {'password': newPassword}})

    return {'status': 'successful'}


# @app.get(
#     "/{id}", response_description="Get a single student", response_model=StudentModel
# )
# async def show_student(file: UploadFile = File(...)):
#     if (student := await db["students"].find_one({"_id": id})) is not None:
#         return student

#     raise HTTPException(status_code=404, detail=f"Student {id} not found")


# @app.put("/{id}", response_description="Update a student", response_model=StudentModel)
# async def update_student(id: str, student: UpdateStudentModel = Body(...)):
#     student = {k: v for k, v in student.dict().items() if v is not None}

#     if len(student) >= 1:
#         update_result = await db["students"].update_one({"_id": id}, {"$set": student})

#         if update_result.modified_count == 1:
#             if (
#                 updated_student := await db["students"].find_one({"_id": id})
#             ) is not None:
#                 return updated_student

#     if (existing_student := await db["students"].find_one({"_id": id})) is not None:
#         return existing_student

#     raise HTTPException(status_code=404, detail=f"Student {id} not found")


# @app.delete("/{id}", response_description="Delete a student")
# async def delete_student(id: str):
#     delete_result = await db["students"].delete_one({"_id": id})

#     if delete_result.deleted_count == 1:
#         return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

#     raise HTTPException(status_code=404, detail=f"Student {id} not found")
