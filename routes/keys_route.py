from fastapi import APIRouter, Header, HTTPException, Depends, Body
from dotenv import dotenv_values
from base_models.models import ShowSuccess, Req, Check, responseWithPrivateKey, responseWithKey
from typing import Union
from datetime import datetime
from utilities.db_handler import db
from dependencies.checkLogin import check
import rsa
import cloudinary
from fastapi.encoders import jsonable_encoder
from utilities.sendEmail import sendMailWithFile


keys_router = APIRouter()
env_vars = dotenv_values(".env")




@keys_router.post(
    "/request-key",
    response_description="Used to request for a key",
    response_model=ShowSuccess
)
async def request_for_a_key(requestEmail: Union[str, None] = Header(default=None), result = Depends(check)):
    try:
        db["requests"].insert_one({
            'sendersEmail': result['email'],
            'receiversEmail': requestEmail,
            'requestStatus': 'pending',
            'privateKeyLink': '',
            "date": datetime.now()
        })
        return {'status': 'Request Sent successfully'}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=404, detail=f"Invalid token")

@keys_router.get(
    "/key-request-status",
    response_description="Check for the status of a key being requested for",
    response_model=ShowSuccess
)
async def get_key_request_status(result = Depends(check)):

    try:
        reqs = []
        req = db["pkLinks"].find({"sendersEmail": result['email']}).sort('i')
        for document in await req.to_list(length=100):
                    reqs.append(document)
        return {'reqStatus': req}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=404, detail=f"Invalid token")
    



@keys_router.post(
    "/approve-sent-keys",
    response_description="Used to approve the keys send from frontend",
    response_model=responseWithPrivateKey
)
async def approve_sent_keys(token: Union[str, None] = Header(default=None), keyL: Union[str, None] = Header(default=None), result = Depends(check)):

    try:
        r = await db["requests"].find_one({'receiversEmail': token['email']})

        if(keyL >= 1024):
            (publicKey, privateKey) = rsa.newkeys(keyL)

            with open('static/keys/publicKey.pem', 'wb') as p:
                p.write(publicKey.save_pkcs1('PEM'))
            with open('static/keys/privateKey.pem', 'wb') as p:
                p.write(privateKey.save_pkcs1('PEM'))

            # with open('static/privateKey.pem', 'rb') as privatefile:
            #     privateKeydata = privatefile.read()

            # with open('static/publicKey.pem', 'rb') as publicfile:
            #     publicKeydata = publicfile.read()

            pk_response = cloudinary.uploader.upload("static/publicKey.pem", resource_type="raw")

            print(pk_response['secure_url'])
            print(pk_response['public_id'])

            db["requests"].update_one({"receiversEmail": result['email']}, {"$set": {'requestStatus': 'approved', 'publicKeyLink': pk_response['secure_url']}})

            return {'successful': True, 'privateKey': 'static/privateKey.pem'}
        else:
            print("Key length should not be less than 1024")
            raise HTTPException(status_code=404, detail=f"Key length should not be less than 1024")

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Internal server error")




@keys_router.post(
    "/generate-key",
    response_description="Used to generate a public and private key for use by the sender and receiver",
    response_model=responseWithKey
)
async def generate_public_and_private_key_pair(token: Union[str, None] = Header(default=None), keyLength: Req = Body(...), result = Depends(check)):
    print(token)
    keyLength = jsonable_encoder(keyLength)
    payload = result
    print(payload)
    print(keyLength)
    keyL = int(keyLength['keyLength'])
    result = check(token)
    if(keyL >= 1024):
        (publicKey, privateKey) = rsa.newkeys(keyL)

        with open('static/keys/publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('static/keys/privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))

        # with open('static/privateKey.pem', 'rb') as privatefile:
        #     privateKeydata = privatefile.read()

        # with open('static/publicKey.pem', 'rb') as publicfile:
        #     publicKeydata = publicfile.read()

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
            "date": datetime.now()
        })

        sendMailWithFile(payload['email'], payload['email'], 'Private Key File', privateKeyMessage, 'static/privateKey.pem')
        
        # sendMail(payload['email'], keyLength['PKReceiversEmail'], privateKeyMessage, str(privateKeydata)[2:-1])

        # sendMail(payload['email'], payload['email'], publicKeyMessage, str(publicKeydata)[2:-1])
        return {'successful': True, 'publicKey': 'static/publicKey.pem', 'privateKey': 'static/privateKey.pem'}

    else:
        print("Key length should not be less than 1024")
        raise HTTPException(status_code=400, detail=f"Key length should not be less than 1024")
    



@keys_router.get(
    "/check-for-new-key",
    response_description="Checks for any new key",
    response_model=Check
)
async def check_if_there_is_a_new_key(result = Depends(check)):
    
    try:

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
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Internal server error")
