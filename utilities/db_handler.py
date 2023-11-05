import motor.motor_asyncio as mongo_motor
from dotenv import load_dotenv
import os
load_dotenv()

client = mongo_motor.AsyncIOMotorClient(os.getenv("MONGO_DB_URL"))
db = client["steg"]