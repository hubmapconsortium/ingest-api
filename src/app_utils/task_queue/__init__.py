import redis
from rq import Queue, Worker, Connection
import logging

logger: logging.Logger = logging.getLogger(__name__)

instance = None


class TaskQueue:

    task_queue = None

    def __init__(self, url: str, queue_name: str):
        conn = redis.from_url(url)
        self.task_queue = Queue('default', connection=conn)

    def get_queue(self):
        return self.task_queue

    @staticmethod
    def create(url: str, queue_name: str) -> None:
        global instance
        if instance is not None:
            raise Exception(
                "An instance of TaskQueue exists already. Use the TaskQueue.instance() method to retrieve it."
            )
        instance = TaskQueue(url, queue_name)

    @staticmethod
    def instance():
        global instance
        if instance is None:
            raise Exception(
                "An instance of TaskQueue does not yet exist. Use TaskQueue.create(...) to create a new instance"
            )
        return instance

    @staticmethod
    def is_initialized() -> bool:
        if instance is None:
            return False
        return True
