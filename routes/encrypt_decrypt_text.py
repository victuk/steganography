from dotenv import dotenv_values
from utilities.db_handler import db
import jwt
from fastapi import APIRouter, HTTPException, Header, UploadFile, File, Depends
from base_models.models import EncryptedText, DecryptedText
from typing import Union
import rsa
import base64
from dependencies.checkLogin import check

text_manipulation_router = APIRouter()
env_vars = dotenv_values(".env")



@text_manipulation_router.post(
    "/encrypt-text",
    response_description="Encrypts text",
    response_model=EncryptedText
)
async def encrypts_text_sent_by_the_user(
    text: Union[str, None] = Header(default=None),
    file: UploadFile = File(...),
    result = Depends(check)):

    try:

        content = file.file.read()

        with open(file.filename, 'wb') as f:
                f.write(content)


        with open(file.filename, 'rb') as publicfile:
            publicKeydata = publicfile.read()

        publicKey = rsa.PublicKey.load_pkcs1(publicKeydata)
        encD = rsa.encrypt(text.encode('utf-8'), publicKey)
        encDToString = base64.urlsafe_b64encode(encD).decode('utf-8')
        
        return {'ciphertext': encDToString}
    
    except Exception as e:
         
         print(e)
         HTTPException(status_code=500, detail=f"Internal server error")


@text_manipulation_router.post(
    "/decrypt-text",
    response_description="Decrypts text sent in",
    response_model=DecryptedText
)
async def decrypts_text_sent_by_the_user(
    ciphertext: Union[str, None] = Header(default=None),
    file: UploadFile = File(...),
    result = Depends(check)):
    
    try:

        content = file.file.read()

        with open(file.filename, 'wb') as f:
                f.write(content)

        with open(file.filename, 'rb') as privatefile:
            privateKeydata = privatefile.read()        

        privateKey = rsa.PrivateKey.load_pkcs1(privateKeydata)

        binText = base64.urlsafe_b64decode(ciphertext)
        decodedVal = rsa.decrypt(binText, privateKey)
        decodedString = decodedVal.decode('utf-8')
        return {'plaintext': decodedString}
    
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Internal server error")
