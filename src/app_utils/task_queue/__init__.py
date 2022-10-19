import redis
from rq import Queue

instance = None


class TaskQueue:

    task_queue = None

    def __init__(self, url: str):
        self.task_queue = Queue("extract_cell_count_job_queue", connection=redis.from_url(url))

    def get_queue(self):
        return self.task_queue

    @staticmethod
    def create(url) -> None:
        global instance
        if instance is not None:
            raise Exception(
                "An instance of TaskQueue exists already. Use the TaskQueue.instance() method to retrieve it."
            )
        instance = TaskQueue(url)

    @staticmethod
    def instance():
        global instance
        if instance is None:
            raise Exception(
                "An instance of TaskQueue does not yet exist. Use TaskQueue.create(...) to create a new instance")
        return instance

    @staticmethod
    def is_initialized() -> bool:
        if instance is None:
            return False
        return True
