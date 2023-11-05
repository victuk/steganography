import motor.motor_asyncio as mongo_motor
from dotenv import dotenv_values
env_vars = dotenv_values(".env")

client = mongo_motor.AsyncIOMotorClient(env_vars["MONGO_DB_URL"])
db = client["steg"]