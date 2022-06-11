import os
from fastapi import FastAPI, Body, HTTPException, status, Header, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from models import ImageFileResponse, StudentModel, Req, StudentModelReply, UpdateStudentModel, responseWithKey, LoginModel, Encrypt, EncryptedText, DecryptedText, Decrypt, ImageFile, HideText
from typing import List, Union
import motor.motor_asyncio
from pymongo import MongoClient
import hashPassword
import jwt
from PIL import Image
import rsa
import base64
from sendEmail import sendMail, sendMailTwo, sendMailWithAttachment
from checkLogin import check
from main import encode_enc, modPix

jwtSecret = '1592e2945cc2e8153171e692c44ceeffd98128be9a79b2d6'
mongUrl = 'mongodb://localhost:27017/'
# os.environ["MONGODB_URL"]

app = FastAPI()

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
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={'created_student':created_student})
        

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
            return {'_id': studentD['_id'], 'username': studentD['username'], 'email': studentD['email'], 'gender': studentD['gender'], 'token':token.decode()}
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

        with open('publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))

        with open('privateKey.pem', 'rb') as privatefile:
            privateKeydata = privatefile.read()

        with open('publicKey.pem', 'rb') as publicfile:
            publicKeydata = publicfile.read()

        publicKeyMessage = 'Public Key to decrypt messages'

        privateKeyMessage = 'Private Key to encrypt messages'

        print('Sender', payload['email'])
        print('Receiver', keyLength['PKReceiversEmail'])
        
        sendMail(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, privateKeydata)

        sendMail(payload['email'], payload['email'], publicKeyMessage, publicKeydata)

    else:
        print("Key length should not be less than 1024")
        raise HTTPException(status_code=404, detail=f"Key length should not be less than 1024")
    return {'successful': True, 'publicKey': publicKeydata}


@app.post(
    "/encrypt-text", response_description="Encrypts text", response_model=EncryptedText
)
async def list_students(token: Union[str, None] = Header(default=None), enc: Encrypt = Body(...)):
    # payload = jwt.decode(token, jwtSecret, algorithms="HS256")
    # print(payload) .decode('utf-8')
    result = check(token)
    if result is not None:
        enc = jsonable_encoder(enc)
        # base64.urlsafe_b64encode(enc['encryptionKey']).decode('utf-8')

        print(bytes(enc['text'], 'utf-8'))
        publicKey = rsa.PublicKey.load_pkcs1(enc['encryptionKey'])
        encD = rsa.encrypt(bytes(enc['text'], 'utf-8'), publicKey)
        encDToString = base64.urlsafe_b64encode(encD).decode('utf8')
        return {'ciphertext': encDToString}
    else:
        raise HTTPException(status_code=404, detail=f"Invalid authentication key")


@app.post(
    "/decrypt-text", response_description="Encrypts text", response_model=DecryptedText
)
async def list_students(token: Union[str, None] = Header(default=None), dec: Decrypt = Body(...)):
    # payload = jwt.decode(token, jwtSecret, algorithms="HS256")
    # print(payload) .decode('utf-8')
    result = check(token)
    if result is not None:
        dec = jsonable_encoder(dec)

        publicKey = rsa.PrivateKey.load_pkcs1(dec['decryptionKey'])
        binText = base64.urlsafe_b64decode(dec['ciphertext'])
        decodedVal = rsa.decrypt(binText, publicKey)
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
            
            if len(f5key) > 24:
                raise HTTPException(status_code=404, detail=f"Maximum keylength exceeded")
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

    


@app.get(
    "/{id}", response_description="Get a single student", response_model=StudentModel
)
async def show_student(id: str):
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
