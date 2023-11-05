from dotenv import dotenv_values
from fastapi import APIRouter, Header, HTTPException, UploadFile, File, Depends
from typing import Union
from utilities.db_handler import db
from base_models.models import ImageFile, ImageFileResponse, ImageLink
from datetime import datetime
import cloudinary.uploader
from utilities.sendEmail import sendMailTwo, sendMailWithAttachment
from utilities.img_manipulation import encode_enc, modPix
from dependencies.checkLogin import check
from utilities.hideImageInImage import merge, unmerge
from PIL import Image

image_manipulation_router = APIRouter()
env_vars = dotenv_values(".env")


@image_manipulation_router.post(
    "/hide-text-in-image", response_description="Hide a text in an image", response_model=ImageFile
)
async def hides_text_inside_a_provided_image(f5key: Union[str, None] = Header(default=None), textToHide: Union[str, None] = Header(default=None), email: Union[str, None] = Header(default=None), file: UploadFile = File(...), result = Depends(check)):
        
        try:
            contents = await file.read()
            with open(file.filename, 'wb') as f:
                f.write(contents)
        except Exception as e:
            print(e)
            raise HTTPException(status_code=404, detail=f"Invalid authentication key")
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
                "date": datetime.now()
            })

            pk_response_two = cloudinary.uploader.upload(fileName + '.txt', resource_type="raw")

            print(pk_response_two['secure_url'])
            print(pk_response_two['public_id'])

            db["fFiveLinks"].insert_one({
                'email': email,
                'sendersEmail': result['email'],
                'pkLink': pk_response_two['secure_url'],
                'pkPublicId': pk_response_two['public_id'],
                "date": datetime.now()
            })

            sendMailTwo(result['email'], result['email'], 'Your f5 key', messageTwo)
            sendMailWithAttachment(result['email'], email, subject, message, new_img_name)

        return {'status': 'Successful'}

@image_manipulation_router.post(
    "/seperate-image", response_description="List all students", response_model=ImageFileResponse
)
async def seperates_image_from_text(f5key: Union[str, None] = Header(default=None), file: UploadFile = File(...), result = Depends(check)):

    try:
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
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Invalid token")  


@image_manipulation_router.post(
    "/hide-image-in-image",
    response_description="Hides a smaller image in a larger image",
    response_model=ImageLink
)
async def hides_an_image_inside_an_image(
    f5key: Union[str, None] = Header(default=None),
    email: Union[str, None] = Header(default=None),
    file: UploadFile = File(...),
    fileTwo: UploadFile = File(...),
    result = Depends(check)):

    try:
        contents = await file.read()
        with open(file.filename, 'wb') as f:
            f.write(contents)

        contentsTwo = await fileTwo.read()
        with open(fileTwo.filename, 'wb') as f:
            f.write(contentsTwo)

    except Exception as e:
        print(e)
        raise HTTPException(status_code=404, detail=f"Invalid token") 
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



@image_manipulation_router.post(
    "/reveal-hidden-image",
    response_description="Get a single student",
    response_model=ImageLink
)
async def show_image_hidden_in_another_image(f5key: Union[str, None] = Header(default=None), file: UploadFile = File(...), result = Depends(check)):
    try:
        fileName = result['email'][:-4]
        key = open(fileName + 'forImg' + '.txt', 'r')
        readKey = key.read()

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
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Server error")  
