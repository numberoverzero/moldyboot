import bloop
import boto3
import json
from pathlib import Path

from ..models import BaseModel, UserManager
from ..security import passwords


boto3.setup_default_session(profile_name="gaas-integ")
engine = bloop.Engine()
engine.bind(base=BaseModel)
user_manager = UserManager(engine)


def load_credentials(filename):
    path = Path(filename).expanduser()
    with path.open(mode="r") as file:
        return json.loads(file.read())


def new_user(credentials_file):
    credentials = load_credentials(credentials_file)
    hashed = passwords.hash(credentials["password"], 12)
    return user_manager.new(credentials["username"], credentials["email"], hashed)
