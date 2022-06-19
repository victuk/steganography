import json
import os
from fastapi import FastAPI, Body, HTTPException, status, Header, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from models import ImageFileResponse, StudentModel, Req, StudentModelReply, UpdateStudentModel, responseWithKey, LoginModel, Encrypt, EncryptedText, DecryptedText, Decrypt, ImageFile, HideText, ImageLink
from typing import List, Union
import motor.motor_asyncio
from pymongo import MongoClient
import hashPassword
import jwt
from PIL import Image
import requests
import rsa
import base64
from sendEmail import sendMail, sendMailTwo, sendMailWithAttachment, sendMailWithFile
from checkLogin import check
from main import encode_enc, modPix
from fastapi.middleware.cors import CORSMiddleware
from sys import stdout
from hideImageInImage import merge, unmerge
from fastapi.staticfiles import StaticFiles

jwtSecret = '1592e2945cc2e8153171e692c44ceeffd98128be9a79b2d6'
mongUrl = 'mongodb://localhost:27017/'
# os.environ["MONGODB_URL"]

app = FastAPI()

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
        passwordMatch =hashPassword.verify_password(student['password'], studentD['password'])
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

        publicKeyMessage = 'Public Key to decrypt messages'

        privateKeyMessage = 'Private Key to encrypt messages'

        print('Sender', payload['email'])
        print('Receiver', keyLength['PKReceiversEmail'])

        sendMailWithFile(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, 'Private Key File', 'static/privateKey.pem')

        sendMailWithFile(payload['email'], payload['email'], publicKeyMessage, 'Public Key File', 'static/publicKey.pem')
        
        # sendMail(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, str(privateKeydata)[2:-1])

        # sendMail(payload['email'], payload['email'], publicKeyMessage, str(publicKeydata)[2:-1])
        return {'successful': True, 'publicKey': 'static/publicKey.pem'}

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
        publicKey = rsa.PublicKey.load_pkcs1(publicKeydata)
        encD = rsa.encrypt(text.encode('utf-8'), publicKey)
        encDToString = base64.urlsafe_b64encode(encD).decode('utf8')
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
                fileName = result['email'][:-4]
                with open(fileName + '.txt', 'w') as f:
                    f.write(f5key)

            f5key = f5key.split(',')

            subject = "Email With Picture Attachment"
            message = "Hi {}, you have received an attachment. Your f5 key is: ".format(studentD['username'])
            messageTwo = "Hi {}, you sent an attachment to {} your f5 key is: {}".format(user['username'], email, str(f5key))
            image = Image.open('./' + file.filename, 'r')
            newimg = image.copy()
            encode_enc(newimg, textToHide)
            new_img_name = 'imageWithHiddenText.png'
            newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))
            sendMailTwo(result['email'], result['email'], 'Your f5 key', messageTwo)
            sendMailWithAttachment(result['email'], email, subject, message + str(f5key), new_img_name)

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
        print(readKey)
        print(f5key)

        content = file.file.read()


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
async def show_student(token: Union[str, None] = Header(default=None), file: UploadFile = File(...)):
    result = check(token)
    if result is not None:
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
    "/{id}", response_description="Get a single student", response_model=StudentModel
)
async def show_student(file: UploadFile = File(...)):
    if (student := await db["students"].find_one({"_id": id})) is not None:
        return student

    raise HTTPException(status_code=404, detail=f"Student {id} not found")


@app.put("/{id}", response_description="Update a student", response_model=StudentModel)
async def update_student(id: str, student: UpdateStudentModel = Body(...)):
    student = {k: v for k, v in student.dict().items() if v is not None}

    if len(student) >= 1:
        update_result = await db["students"].update_one({"_id": id}, {"$set": student})

        if update_result.modified_count == 1:
            if (
                updated_student := await db["students"].find_one({"_id": id})
            ) is not None:
                return updated_student

    if (existing_student := await db["students"].find_one({"_id": id})) is not None:
        return existing_student

    raise HTTPException(status_code=404, detail=f"Student {id} not found")


@app.delete("/{id}", response_description="Delete a student")
async def delete_student(id: str):
    delete_result = await db["students"].delete_one({"_id": id})

    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

    raise HTTPException(status_code=404, detail=f"Student {id} not found")
