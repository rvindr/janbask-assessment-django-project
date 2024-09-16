from pymongo.mongo_client import MongoClient
from dotenv import load_dotenv
import os


# load environment variables
load_dotenv()

# create a new client and connect to the server
client = MongoClient(os.getenv("MONGODB_URI"))

try:
    client.admin.command("ping")
    print("Pinged your deployment. You successfully connect to MongoDb!")

except Exception as e:
    print(e)

db = client.authentication
users_collection = db.users
token_collection = db.token_blacklist

# ---------------------Role and permission-------
roles_collection = db.roles
permissions_collection = db.permissions
logs_collection = db.user_logs
