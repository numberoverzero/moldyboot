# 0. Install redis
# 1. Load aws security credentials
# 2. Create venv and pip install moldyboot
#
# apt-get install redis-server
#
# cat <<EOF > /service/api/.aws
# {
#     "aws_access_key_id": ...,
#     "aws_secret_access_key": ...
# }
# EOF
#
# virtualenv -p python3.5 /services/api/.venv
# source /services/api/.venv/bin/activate
# pip install path/to/moldyboot/project

import bloop
import boto3
import falcon
import falcon_cors
import json
import redis
import rq

from moldyboot.middleware import Authentication, TranslateJSON
from moldyboot.controllers import KeyManager, UserManager
from moldyboot.models import BaseModel
from moldyboot.resources import Keys, Signup, Verifications
from moldyboot.tasks import AsyncTasks

ROOT = "/services/api"

redis_connection = redis.StrictRedis(host="127.0.0.1", port=6379)
queue = rq.Queue(connection=redis_connection)

with open(ROOT + "/.credentials/aws") as f:
    credentials = json.load(f)
session = boto3.session.Session(**credentials)
engine = bloop.Engine(
    dynamodb=session.client("dynamodb"),
    dynamodbstreams=session.client("dynamodbstreams")
)
engine.bind(BaseModel)

async_tasks = AsyncTasks(queue)
key_manager = KeyManager(engine)
user_manager = UserManager(engine)

cors = falcon_cors.CORS(
    allow_origins_list=[
        "https://console.moldyboot.com",
        "https://moldyboot.com"
    ],
    allow_all_methods=True,
    allow_all_headers=True,
    max_age="600")
api = application = falcon.API(
    middleware=[
        cors.middleware,
        TranslateJSON(),
        Authentication(key_manager, user_manager)
    ]
)
api.add_route("/keys", Keys(key_manager))
api.add_route("/signup", Signup(user_manager, async_tasks))
api.add_route("/verify/{user_id}/{verification_code}", Verifications(user_manager))
