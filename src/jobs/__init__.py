from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Optional, Union
from uuid import UUID, uuid4

from redis import Redis, from_url
from rq import Queue, get_current_job
from rq.job import Job, JobStatus, NoSuchJobError

logger: logging.Logger = logging.getLogger(__name__)

_instance = None

JOBS_PREFIX = "rq:job:"  # The prefix for all job keys in Redis


@dataclass(frozen=True)
class JobResult:
    success: bool
    results: dict


class JobSubject(str, Enum):
    ENTITY = "entity"
    METADATA = "metadata"


class JobType(str, Enum):
    VALIDATE = "validate"
    REGISTER = "register"

    @property
    def noun(self) -> str:
        if self == JobType.VALIDATE:
            return "validation"
        return "registration"


class JobVisibility(str, Enum):
    """Enum that represents whether a job is returned to the end user or not. Public
    jobs are returned to the end user, while private jobs are not. Results of private
    jobs also have a shorter lifetime in the queue.
    """

    PUBLIC = "public"
    PRIVATE = "private"


class TooManyJobsFoundError(Exception):
    pass


class JobQueue:
    def __init__(self, url: str, queue_name: str = "default"):
        conn = from_url(url)
        self._job_queue = Queue(queue_name, connection=conn)
        self._redis = conn

    @property
    def queue(self) -> Queue:
        return self._job_queue

    @property
    def redis(self) -> Redis:
        return self._redis

    @staticmethod
    def create(url: str, queue_name: str = "default") -> None:
        global _instance
        if _instance is not None:
            raise Exception(
                "An instance of JobQueue exists already. Use the JobQueue.instance() method to retrieve it."
            )
        _instance = JobQueue(url, queue_name)

    @staticmethod
    def instance() -> JobQueue:
        global _instance
        if _instance is None:
            raise Exception(
                "An instance of JobQueue does not yet exist. Use JobQueue.create(...) to create a new instance"
            )
        return _instance

    @staticmethod
    def is_initialized() -> bool:
        if _instance is None:
            return False
        return True

    def enqueue_job(
        self,
        user: dict,
        description: str,
        metadata: Optional[dict],
        job_id: str,
        job_func,
        job_kwargs,
        visibility: JobVisibility = JobVisibility.PUBLIC,
    ) -> Job:
        """Enqueue a job in the queue.

        Parameters
        ----------
        user : dict
            The user's 'id' and 'email' that is enqueuing the job.
        description : str
            The description of the job.
        metadata : Optional[dict]
            Additional metadata to store with the job.
        job_id : str
            The job id.
        job_func : func
            Job function to execute.
        job_kwargs : dict
            Job function keyword arguments.
        visibility : JobVisibility
            The visibility of the job. Defaults to JobVisibility.PUBLIC.

        Returns
        -------
        Job
            The RQ Job object.
        """
        if visibility == JobVisibility.PRIVATE:
            lifetime = timedelta(days=1).total_seconds()
        else:
            lifetime = timedelta(days=7).total_seconds()

        queue_id = create_queue_id(user["id"], job_id)
        job = self.queue.enqueue(
            job_func,
            kwargs=job_kwargs,
            job_id=queue_id,
            job_timeout=18000,
            ttl=lifetime,
            result_ttl=lifetime,
            error_ttl=lifetime,
            description=description,
        )

        job.meta["user"] = user
        job.meta["visibility"] = visibility
        job.meta["progress"] = 0
        if metadata and len(metadata) > 0:
            job.meta.update(metadata)
        job.save()

        return job

    def query_job(self, query: str) -> Job:
        """Get a RQ Job from Redis using a scan query.

        See Redis SCAN command for more information on the query format.

        Parameters
        ----------
        query : str
            The query to use to search for the job.

        Returns
        -------
        Job
            The RQ Job object.

        Raises
        ------
        NoSuchJobError
            If the job is not found.
        TooManyJobsFoundError
            If multiple jobs are found with the query. Should not happen.
        """
        queue_ids = [
            queue_id.decode("utf-8").removeprefix(JOBS_PREFIX)
            for queue_id in self._redis.scan_iter(query)
        ]
        if len(queue_ids) == 0:
            raise NoSuchJobError("Job not found")
        if len(queue_ids) > 1:
            raise TooManyJobsFoundError("Multiple jobs found with from query")

        return Job.fetch(queue_ids[0], connection=self._redis)

    def query_jobs(self, query: str) -> list[Job]:
        """Get a list of RQ Jobs from Redis using a scan query.

        Parameters
        ----------
        query : str
            The query to use to search for the jobs.

        Returns
        -------
        list[Job]
            The list of RQ Job objects.
        """
        queue_ids = [
            queue_id.decode("utf-8").removeprefix(JOBS_PREFIX)
            for queue_id in self._redis.scan_iter(query)
        ]
        return Job.fetch_many(queue_ids, connection=self._redis)


def create_queue_id(user_id: str, job_id: Optional[Union[str, UUID]] = None) -> str:
    """Create a unique queue id for a user.

    This is used as the actual key for the job in the queue. We prefix the user_id
    to the job_id to ensure that the queue_id is unique for each user.

    Parameters
    ----------
    user_id : str
        The user uuid.
    job_id : Optional[Union[str, UUID]]
        The job uuid.

    Returns
    -------
    str
        The queue_id
    """
    if job_id is None:
        job_id = uuid4()
    return f"{user_id}:{job_id}"


def split_queue_id(queue_id: str) -> tuple:
    """Split the queue_id into the user_id and job_id

    Parameters
    ----------
    queue_id : str
        The queue_id

    Returns
    -------
    tuple
        The user_id and job_id
    """
    user_id, job_id = queue_id.split(":")
    return user_id, job_id


def job_to_response(job: Job, admin: bool = False) -> dict:
    _, job_id = split_queue_id(job.id)
    status = job.get_status()
    results = None
    errors = None
    if status == JobStatus.FINISHED:
        result: JobResult = job.result
        status = "complete" if result.success else "error"
        results = result.results if result.success else None
        errors = result.results if not result.success else None

    if status == JobStatus.FAILED:
        if admin:
            # Give admins the stack trace
            errors = {"message": str(job.exc_info)}
        else:
            errors = {
                "message": (
                    "Something went wrong while processing the job. Please resubmit. "
                    "If the problem persists, contact support."
                )
            }

    return {
        "job_id": job_id,
        "register_job_id": job.meta.get("register_job_id"),
        "referrer": job.meta.get("referrer", {}),
        "description": job.description,
        "status": status.title(),
        "user": job.meta.get("user", {}),
        "progress": job.meta.get("progress", 100),
        "started_timestamp": (
            int(job.started_at.timestamp() * 1000) if job.started_at else None
        ),
        "ended_timestamp": (
            int(job.ended_at.timestamp() * 1000) if job.ended_at else None
        ),
        "results": results,
        "errors": errors,
    }


def get_display_job_status(job: Job) -> str:
    """Get the job status that is displayed to the user.

    Parameters
    ----------
    job : Job
        The RQ Job object.

    Returns
    -------
    str
        The formatted job status.
    """
    status = job.get_status()
    if status == JobStatus.FINISHED:
        result: JobResult = job.result
        status = "complete" if result.success else "error"

    return status.title()


def create_job_description(
    subject: JobSubject,
    job_type: JobType,
    entity_type: str,
    subtype: Optional[str],
    filename: Optional[str],
) -> str:
    """Create a job description for a job.

    Parameters
    ----------
    subject : JobSubject
        The subject of the job.
    job_type : JobType
        The type of job.
    entity_type : str
        The entity type ("Source", "Sample").
    subtype : Optional[str]
        The optional subtype ("Mouse", "Block", "Section", "Suspension").
    filename : Optional[str]
        The optional filename.

    Returns
    -------
    str
        The job description.
    """

    subject = subject.title()
    job_type = job_type.noun.lower()
    entity_type = entity_type.title()
    formatted_subtype = f" {subtype.title()}" if subtype else ""
    filename_suffix = f" from file {filename}" if filename else ""

    return f"{subject} {job_type} for {entity_type}{formatted_subtype}{filename_suffix}"


def update_job_progress(progress: float, job: Optional[Job] = None):
    """Update the progress of a job.

    Parameters
    ----------
    progress : float
        The percentage progress of the job (0-100).
    job : Optional[Job]
        The RQ Job object. Defaults to the current job.
    """
    if job is None:
        job = get_current_job()

    progress = round(progress)
    if progress < 0:
        progress = 0
    if progress > 100:
        progress = 100

    meta = job.get_meta()
    meta["progress"] = progress
    job.meta = meta
    job.save_meta()


def update_job_metadata(job: Job, metadata: dict) -> None:
    """Update the metadata of a given job. This will update metadata, not replace it entirely.

    Parameters
    ----------
    job : Job
        The RQ Job object.
    metadata : dict
        The metadata to update.
    """
    meta = job.get_meta()
    meta.update(metadata)
    job.meta = meta
    job.save_meta()
