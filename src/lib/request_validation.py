import json
from collections.abc import Iterable
from typing import Union
from urllib.parse import urlparse
from uuid import UUID

from jobs import JobType


def get_validated_job_id(data: dict) -> str:
    """Get the job ID from the request data and validate it

    Parameters
    ----------
    data : dict
        The request data

    Returns
    -------
    str
        The validated job UUID

    Raises
    ------
    ValueError
        If the job ID is missing or not a valid UUID
    """
    job_id = data.get("job_id")
    if not job_id:
        raise ValueError("Missing job ID")
    try:
        UUID(job_id)
    except ValueError:
        raise ValueError("Invalid job ID")

    return job_id


def get_validated_group_uuid(
    data: dict, user_group_ids: list, user_is_admin: bool
) -> str:
    """Get the group UUID from the request data and validate it

    Parameters
    ----------
    data : dict
        The request data
    user_group_ids : list
        The groups the user is a member of
    user_is_admin : bool
        Whether the user is a data admin

    Returns
    -------
    str
        The validated group UUID

    Raises
    ------
    ValueError
        If the group UUID is missing, the user doesn't belong to the group,
        or the group id not a valid UUID
    """
    group_uuid = data.get("group_uuid")
    if not group_uuid:
        raise ValueError("Missing group UUID")

    if group_uuid not in user_group_ids and not user_is_admin:
        raise ValueError(
            "Entities can only be registered to groups you are a member of"
        )

    try:
        UUID(group_uuid)
    except ValueError:
        raise ValueError("Invalid job ID")

    return group_uuid


def get_validated_referrer(data: dict, job_type: JobType) -> dict:
    """Get the referrer from the request data and validate it

    Parameters
    ----------
    data : dict
        The request data
    job_type : JobType
        The job type to validate against

    Returns
    -------
    dict
        The validated referrer with the job type and path

    Raises
    ------
    ValueError
        If the referrer is missing, the type is missing or invalid, the path URL is
        missing, or the path URL is invalid
    """
    referrer = data.get("referrer", "{}")
    if isinstance(referrer, str):
        referrer = json.loads(referrer)

    if len(referrer) < 1:
        raise ValueError("Missing referrer")

    if "type" not in referrer or referrer["type"] != job_type.value:
        raise ValueError(f"Invalid referrer {referrer}")

    if "path" not in referrer:
        raise ValueError("Missing referrer path")

    path = referrer["path"].replace(" ", "")
    parsed = urlparse(path)
    if parsed.scheme != "" or parsed.netloc != "" or len(parsed.path) < 1:
        raise ValueError(f"Invalid referrer path URL {path}")

    query = f"?{parsed.query}" if parsed.query else ""
    return {
        "type": job_type.value,
        "path": f"{parsed.path}{query}",
    }


def get_validated_uuids(data: Union[dict, Iterable]) -> list:
    """Validate a list of UUIDs

    Parameters
    ----------
    data : Union[dict, list]
        The request body dict or list of possible UUIDs

    Returns
    -------
    list
        The list of validated UUID strings

    Raises
    ------
    ValueError
        If any of the UUIDs are invalid
    """
    if isinstance(data, dict):
        data = data.get("uuids", [])
    if not isinstance(data, list):
        data = list(data)

    invalid = [uuid for uuid in data if not is_uuid(uuid)]
    if len(invalid) > 0:
        raise ValueError(f"Invalid UUIDs: {', '.join(invalid)}")

    return data


def is_uuid(uuid: str) -> bool:
    """Check if a string is a valid UUID

    Parameters
    ----------
    uuid : str
        The potential UUID string

    Returns
    -------
    bool
        Whether the string is a valid UUID
    """
    try:
        UUID(uuid)
        return True
    except ValueError:
        return False
