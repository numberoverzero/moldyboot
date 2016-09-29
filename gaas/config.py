import bloop
import boto3.session
import redis
import rq
import urllib.parse

from gaas.controllers import KeyManager, UserManager
from gaas.models import BaseModel
from gaas.tasks import AsyncTasks

api_endpoint = urllib.parse.urlsplit("http://127.0.0.1:8010")
console_endpoint = urllib.parse.urlsplit("http://127.0.0.1:8020")
redis_port = 6379

redis_connection = redis.StrictRedis(port=redis_port)
queue = rq.Queue(connection=redis_connection)

session = boto3.session.Session(profile_name="gaas-integ")
engine = bloop.Engine(client=bloop.Client(boto_client=session.client("dynamodb")))
engine.bind(base=BaseModel)

key_manager = KeyManager(engine)
user_manager = UserManager(engine)
async_tasks = AsyncTasks(queue)
