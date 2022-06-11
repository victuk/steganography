from xmlrpc.client import Boolean
from bson import ObjectId
from typing import Optional, List, Union
from pydantic import BaseModel, Field, EmailStr

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class StudentModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)


    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "username": "JaneDoe",
                "email": "jdoe@example.com",
                "gender": "male",
                "password": "12345678"
            }
        }

class Req(BaseModel):
    keyLength: str = Field(...)
    PKReceiversEmail: EmailStr = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "KeyLength": "1024"
            }
        }

class StudentModelReply(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str = Field(...)
    email: EmailStr = Field(...)
    gender: str = Field(...)
    token: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "username": "JaneDoe",
                "email": "jdoe@example.com",
                "gender": "male",
                "password": "12345678"
            }
        }

class UpdateStudentModel(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    gender: Optional[str]
    password: Optional[str]
    token: Optional[str]

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "username": "JaneDoe",
                "email": "jdoe@example.com",
                "gender": "male",
                "password": "12345678"
            }
        }

class responseWithKey(BaseModel):
    publicKey: Optional[str]
    successful: Optional[bool]

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "username": "JaneDoe",
                "email": "jdoe@example.com",
                "gender": "male",
                "password": "12345678"
            }
        }

class LoginModel(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(...)


    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "email": "jdoe@example.com",
                "password": "12345678"
            }
        }

class Encrypt(BaseModel):
    text: str = Field(...)
    encryptionKey: bytes = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "email": "jdoe@example.com",
                "password": "12345678"
            }
        }

class EncryptedText(BaseModel):
    ciphertext: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "ciphertext": "ewwwssroihowfioawsdivhoaiv"
            }
        }


class Decrypt(BaseModel):
    ciphertext: str = Field(...)
    decryptionKey: bytes = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "text": "Hello",
                "decryptionKey": "oewfihowiehfweifhoih"
            }
        }

class DecryptedText(BaseModel):
    plaintext: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "ciphertext": "ewwwssroihowfioawsdivhoaiv"
            }
        }

class ImageFile(BaseModel):
    status: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "ciphertext": "ewwwssroihowfioawsdivhoaiv"
            }
        }

class ImageFileResponse(BaseModel):
    ciphertext: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "ciphertext": "ewwwssroihowfioawsdivhoaiv"
            }
        }

class HideText(BaseModel):
    text: str = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "text": "ewwwssroihowfioawsdivhoaiv"
            }
        }
