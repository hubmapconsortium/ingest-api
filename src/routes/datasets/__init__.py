from flask import Blueprint, request, Response, current_app, jsonify
import logging
from rq import Retry

from ingest_file_helper import IngestFileHelper

from hubmap_commons.exceptions import HTTPException

from app_utils.request_validation import require_json
from app_utils.task_queue import TaskQueue

from worker.utils import thread_extract_cell_count_from_secondary_analysis_files_for_sample_uuid, sample_ds_uuid_files, get_ds_path, ResponseException


datasets_blueprint = Blueprint('datasets', __name__)

logger: logging.Logger = logging.getLogger(__name__)


@datasets_blueprint.route('/dataset/begin-extract-cell-count-from-secondary-analysis-files-async', methods=['POST'])
def begin_extract_cell_count_from_secondary_analysis_files_async():
    """Spatial Api requests cell type counts for the sample which is returned asynchronously by the thread"""
    require_json(request)
    sample_uuid: str = ''
    try:
        ingest_helper = IngestFileHelper(current_app.config)
        sample_uuid: str = request.json['sample_uuid']
        ds_files: dict = sample_ds_uuid_files(request.json['ds_uuids'], ingest_helper)
        spatial_url: str = current_app.config['SPATIAL_WEBSERVICE_URL'].rstrip('/')
        task_queue = TaskQueue.instance().get_queue()
        args = (sample_uuid, ds_files, spatial_url,)
        job = task_queue.enqueue(thread_extract_cell_count_from_secondary_analysis_files_for_sample_uuid,
                                 args=args,
                                 retry=Retry(max=3))
        logger.info(f'Task: {job.id} enqueued at {job.enqueued_at} with args: {args}')
        return Response("Processing has been initiated", 202)
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for sample_uuid {sample_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error in extract_cell_count_from_secondary_analysis_files: " + str(e), 500)


@datasets_blueprint.route('/uploads/<ds_uuid>/file-system-abs-path', methods=['GET'])
@datasets_blueprint.route('/datasets/<ds_uuid>/file-system-abs-path', methods=['GET'])
def get_file_system_absolute_path(ds_uuid: str):
    try:
        ingest_helper = IngestFileHelper(current_app.config)
        return jsonify({'path': get_ds_path(ds_uuid, ingest_helper)}), 200
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for {ds_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500)
