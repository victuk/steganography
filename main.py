from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import cloudinary
# import cloudinary.uploader
# import cloudinary.api
import os
import uvicorn
from dotenv import dotenv_values, load_dotenv
from routes.authentication import authentication_router
from routes.encrypt_decrypt_text import text_manipulation_router
from routes.image_manipulation_routes import image_manipulation_router
from routes.keys_route import keys_router
from routes.user_profile import user_router
load_dotenv()


app = FastAPI(
    title="Infocrypt steganography API.",
    description="Used for encryption and steganography. With this API you can hide an image inside an image, \
        encrypt text before hiding inside an image, seperate image from image, seperate image from text, decrypt text, etc."
)
env_vars = dotenv_values(".env")
cloudinary.config( 
  cloud_name = os.getenv("cloudinary_api_name"), 
  api_key = os.getenv("cloudinary_api_key"), 
  api_secret = os.getenv("cloudinary_api_secret"),
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




app.include_router(
    authentication_router,
    tags=["Authentication"],
    prefix="/v1/authentication",
)

app.include_router(
    text_manipulation_router,
    tags=["Text manipulation"],
    prefix="/v1/text"
)

app.include_router(
    image_manipulation_router,
    tags=["Image manipulation"],
    prefix="/v1/images"
)

app.include_router(
    keys_router,
    tags=["Handles key generation, request, etc"],
    prefix="/v1/keys"
)

app.include_router(
    user_router,
    tags=["User Profile"],
    prefix="/v1/user"
)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT")), reload=True)
