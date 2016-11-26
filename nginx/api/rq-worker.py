import bloop
import boto3
import json
import logging
import redis
import rq
import urllib.parse

from moldyboot.controllers import KeyManager, UserManager
from moldyboot.models import BaseModel
from moldyboot.tasks import AsyncTasks, RedisContext

ROOT = "/services/api"
logger = logging.getLogger(__name__)


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

api_endpoint = urllib.parse.urlsplit("https://api.moldyboot.com")

# Inject dependencies for worker threads =============================================================================
RedisContext.initialize(user_manager, key_manager, session, api_endpoint)


# Retries ============================================================================================================
# https://gist.github.com/spjwebster/6521272
MAX_FAILURES = 3


def retry_handler(job, *exc_info):
    job.meta.setdefault('failures', 0)
    job.meta['failures'] += 1

    # Too many failures
    if job.meta['failures'] >= MAX_FAILURES:
        logger.warn('job %s: failed too many times times - moving to failed queue' % job.id)
        job.save()
        return True

    # Requeue job and stop it from being moved into the failed queue
    logger.warn('job %s: failed %d times - retrying' % (job.id, job.meta['failures']))

    if queue.name == job.origin:
        queue.enqueue_job(job)
        return False

    # Can't find queue, which should basically never happen as we only work jobs that match the given queue names and
    # queues are transient in rq.
    logger.warn('job %s: cannot find queue %s - moving to failed queue' % (job.id, job.origin))
    return True


with rq.Connection():
    worker = rq.Worker([queue])
    worker.push_exc_handler(retry_handler)
    worker.work()
