from flask import Blueprint, request, Response, current_app, jsonify
import requests
import os
import json
from typing import List
from threading import Thread, current_thread, Lock
from datetime import datetime
import logging
from ingest_file_helper import IngestFileHelper
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException

from app_utils.request_validation import require_json
from app_utils.misc import __get_dict_prop
from app_utils.entity import __get_entity

datasets_blueprint = Blueprint('datasets', __name__)
logger: logging.Logger = logging.getLogger(__name__)
logger_lock = Lock()


class ResponseException(Exception):
    """Return a HTTP response from deep within the call stack"""
    def __init__(self, message: str, stat: int):
        self.message: str = message
        self.status: int = stat

    @property
    def response(self) -> Response:
        logger.error(f'message: {self.message}; status: {self.status}')
        return Response(self.message, self.status)


# https://stackoverflow.com/questions/48745240/python-logging-in-multi-threads
def h5ad_file_analysis_updating_cell_type_counts(h5ad_file: str,
                                                 cell_type_counts: dict) -> None:
    """Allow the accumulation of cell type counts found in h5ad_files.
    Hint: Object function parameters in Python are 'call by address' """
    # https://www.hdfgroup.org/
    import anndata
    sec_an = anndata.read_h5ad(h5ad_file)
    if 'predicted.ASCT.celltype' in sec_an.obs:
        df = sec_an.obs[['predicted.ASCT.celltype']]
        for index, row in df.iterrows():
            cell_type: str = row.tolist()[0]
            if cell_type not in cell_type_counts:
                cell_type_counts[cell_type] = 1
            else:
                cell_type_counts[cell_type] += 1


# This is the time-consuming part of the process. It is called from a thread to prevent a HTTP response timeout.
def extract_cell_type_counts(ds_files: dict) -> dict:
    """Accumulate the cell type counts from the given dataset files"""
    cell_type_counts: dict = {}
    for ds_uuid, h5ad_file in ds_files.items():
        h5ad_file_analysis_updating_cell_type_counts(h5ad_file, cell_type_counts)
        logger.info(
            f"Extracted cell count from secondary analysis file for ds_uuid: {ds_uuid}; h5ad_file: {h5ad_file}")
    return cell_type_counts


def get_ds_path(ds_uuid: str,
                ingest_helper: IngestFileHelper) -> str:
    """Get the path to the dataset files"""
    dset = __get_entity(ds_uuid, auth_header=request.headers.get("AUTHORIZATION"))
    ent_type = __get_dict_prop(dset, 'entity_type')
    group_uuid = __get_dict_prop(dset, 'group_uuid')
    if ent_type is None or ent_type.strip() == '':
        raise ResponseException(f"Entity with uuid:{ds_uuid} needs to be a Dataset or Upload.", 400)
    if ent_type.lower().strip() == 'upload':
        return ingest_helper.get_upload_directory_absolute_path(group_uuid=group_uuid, upload_uuid=ds_uuid)
    is_phi = __get_dict_prop(dset, 'contains_human_genetic_sequences')
    if ent_type is None or not ent_type.lower().strip() == 'dataset':
        raise ResponseException(f"Entity with uuid:{ds_uuid} is not a Dataset or Upload", 400)
    if group_uuid is None:
        raise ResponseException(f"Unable to find group uuid on dataset {ds_uuid}", 400)
    if is_phi is None:
        raise ResponseException(f"Contains_human_genetic_sequences is not set on dataset {ds_uuid}", 400)
    return ingest_helper.get_dataset_directory_absolute_path(dset, group_uuid, ds_uuid)


def sample_ds_uuid_files(ds_uuids: List[str],
                         ingest_helper: IngestFileHelper) -> dict:
    """Return a dict which associates the dataset uuid with the file for processing by the thread"""
    ds_files: dict = {}
    for ds_uuid in ds_uuids:
        h5ad_file: str = get_ds_path(ds_uuid, ingest_helper) + '/secondary_analysis.h5ad'
        if os.path.exists(h5ad_file):
            ds_files.update({ds_uuid: h5ad_file})
        else:
            logger.error(
                f"For ds_uuid: {ds_uuid}; Missing extracted cell count from secondary analysis h5ad_file: {h5ad_file}")
    return ds_files


def thread_extract_cell_count_from_secondary_analysis_files_for_sample_uuid(sample_uuid: str,
                                                                            ds_files: dict,
                                                                            spatial_url: str):
    """Aggregate the cell type counts and send them back to Spatial-Api"""
    start = datetime.now()
    # TODO: Does logger_lock also need to be used by ALL calls to logger and not just the ones in the thread?
    with logger_lock:
        logger.info(f'Thread {current_thread().name} started!')
    url = f"{spatial_url}/sample/extracted-cell-count-from-secondary-analysis-files"
    # Because this thread may take a long time we send a token that won't timeout...
    auth_helper_instance = AuthHelper.instance()
    headers: dict = {
        'Authorization': f'Bearer {auth_helper_instance.getProcessSecret()}',
        'X-Hubmap-Application': 'ingest-api',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    data: dict = {
        'sample_uuid': sample_uuid,
        'cell_type_counts': extract_cell_type_counts(ds_files)
    }
    # Send the data that it time-consuming to produce, spacial-api will finish up with this but respond back
    # to us that it is simply "working on it". There is no loop to close here. Status checked just to log it.
    resp: Response = requests.put(url, headers=headers, data=json.dumps(data))
    with logger_lock:
        if resp.status_code != 202:
            logger.error(f'Thread {current_thread().name} unexpected response ({resp.status_code}) for {url} while processing sample {sample_uuid}')
        logger.info(f'Thread {current_thread().name} done; sample {sample_uuid};' +\
                    f' execution time [h:mm:ss.xxxxxx]: {datetime.now()-start}!')


@datasets_blueprint.route('/dataset/begin-extract-cell-count-from-secondary-analysis-files-async', methods=['POST'])
def begin_extract_cell_count_from_secondary_analysis_files_async():
    """Spatial Api requests cell type counts for the sample which is returned asynchronously by the thread"""
    require_json(request)
    sample_uuid: str = ''
    try:
        start = datetime.now()
        ingest_helper = IngestFileHelper(current_app.config)
        sample_uuid: str = request.json['sample_uuid']
        ds_files: dict = sample_ds_uuid_files(request.json['ds_uuids'], ingest_helper)
        spatial_url: str = current_app.config['SPATIAL_WEBSERVICE_URL'].rstrip('/')
        thread = Thread(target=thread_extract_cell_count_from_secondary_analysis_files_for_sample_uuid,
                        args=[sample_uuid, ds_files, spatial_url],
                        name=f'extract_cell_count_for_sample_uuid_{sample_uuid}')
        thread.start()
        logger.info(
            f"begin_extract_cell_count_from_secondary_analysis_files_async done; sample {sample_uuid};"
            f" execution time [h:mm:ss.xxxxxx]: {datetime.now() - start}!")
        return Response("Processing has been initiated", 202)
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for sample_uuid {sample_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error in extract_cell_count_from_secondary_analysis_files: " + str(e), 500)


# This is the non-threaded version of the above which is DEPRECATED....
@datasets_blueprint.route('/dataset/extract-cell-count-from-secondary-analysis-files', methods=['POST'])
def extract_cell_count_from_secondary_analysis_files():
    try:
        require_json(request)
        ingest_helper = IngestFileHelper(current_app.config)
        ds_files: dict = sample_ds_uuid_files(request.json['ds_uuids'], ingest_helper)
        return jsonify({'cell_type_counts': extract_cell_type_counts(ds_files)}), 200
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for dataset: " +
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
