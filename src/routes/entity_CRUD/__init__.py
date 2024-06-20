from uuid import uuid4
from flask import Blueprint, jsonify, request, Response, current_app, json
import logging
import requests
import os
import time
from hubmap_sdk import Entity, EntitySdk
from threading import Thread
from redis import from_url

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper
from hubmap_commons import string_helper
from utils.string import equals
from utils.rest import (
    StatusCodes, abort_bad_req, abort_forbidden, abort_internal_err, abort_not_found, rest_response
)
from rq.job import JobStatus

from lib.decorators import User, require_data_admin, require_json

from jobs import JobQueue, JobVisibility
from jobs.modification.datasets import update_datasets_uploads
from jobs.submission.datasets import submit_datasets
from lib.dataset_helper import DatasetHelper
from lib.ingest_file_helper import IngestFileHelper
from lib.exceptions import ResponseException
from lib.file import set_file_details
from lib.file_upload_helper import UploadFileHelper
from lib import get_globus_url
from lib.datacite_doi_helper import DataCiteDoiHelper
from lib.neo4j_helper import Neo4jHelper
from lib.request_validation import get_validated_uuids

# Local modules
from routes.auth import get_auth_header_dict

from lib.file import get_csv_records, check_upload, files_exist
from lib.services import get_associated_sources_from_dataset

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)


ACCEPTED_BULK_UPDATE_FIELDS = ["uuid", "assigned_to_group_name", "ingest_task", "status"]


@entity_CRUD_blueprint.route('/datasets', methods=['PUT'])
@entity_CRUD_blueprint.route('/uploads', methods=['PUT'])
@require_data_admin(param='token')
@require_json(param='entities')
def bulk_update_datasets_uploads(entities: list, token: str, user: User):
    if request.path == "/datasets":
        entity_type = 'dataset'
    else:
        entity_type = 'upload'

    if len(entities) == 0:
        abort_bad_req(f"A list of {entity_type}s with updated fields is required")

    uuids = [e.get("uuid") for e in entities]
    if None in uuids:
        abort_bad_req(f"All {entity_type}s must have a 'uuid' field")
    if len(set(uuids)) != len(uuids):
        abort_bad_req(f"{entity_type}s must have unique 'uuid' fields")

    if not all(set(e.keys()).issubset(ACCEPTED_BULK_UPDATE_FIELDS) for e in entities):
        abort_bad_req(
            f"Some {entity_type}s have invalid fields. Acceptable fields are: " +
            ", ".join(ACCEPTED_BULK_UPDATE_FIELDS)
        )

    uuids = set([e["uuid"] for e in entities])
    try:
        fields = {"uuid", "entity_type"}
        db_entities = Neo4jHelper.get_entities_by_uuid(uuids, fields)
    except Exception as e:
        logger.error(f"Error while submitting datasets: {str(e)}")
        abort_internal_err(str(e))

    diff = uuids.difference({e["uuid"] for e in db_entities if equals(e["entity_type"], entity_type)})
    if len(diff) > 0:
        abort_not_found(f"No {entity_type} found with the following uuids: {', '.join(diff)}")

    job_queue = JobQueue.instance()
    job_id = uuid4()
    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=update_datasets_uploads,
        job_kwargs={
            "job_id": job_id,
            "entity_updates": entities,
            "token": token,
        },
        user={"id": user.uuid, "email": user.email},
        description=f"Bulk {entity_type} update",
        metadata={},
        visibility=JobVisibility.PRIVATE
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err(f"{entity_type} update job failed to start")

    # return a 202 reponse with the accepted dataset uuids
    return jsonify(list(uuids)), 202
