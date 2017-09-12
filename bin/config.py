import bloop
import boto3.session
import redis
import rq
import urllib.parse

from moldyboot.controllers import KeyManager, UserManager
from moldyboot.models import BaseModel
from moldyboot.tasks import AsyncTasks

api_endpoint = urllib.parse.urlsplit("http://127.0.0.1:8010")
console_endpoint = urllib.parse.urlsplit("http://127.0.0.1:8020")
redis_port = 6379

redis_connection = redis.StrictRedis(port=redis_port)
queue = rq.Queue(connection=redis_connection)

session = boto3.session.Session(profile_name="moldyboot-crossj@ubuntu-16")
engine = bloop.Engine(
    dynamodb=session.client("dynamodb"),
    dynamodbstreams=session.client("dynamodbstreams")
)
engine.bind(BaseModel)

key_manager = KeyManager(engine)
user_manager = UserManager(engine)
async_tasks = AsyncTasks(queue)
