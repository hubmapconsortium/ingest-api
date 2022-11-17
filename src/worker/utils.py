from flask import request, Response
import requests
import os
import json
from typing import List
import logging

from ingest_file_helper import IngestFileHelper

from hubmap_commons.hm_auth import AuthHelper

from app_utils.misc import __get_dict_prop
from app_utils.entity import __get_entity


logger: logging.Logger = logging.getLogger(__name__)


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


def extract_cell_count_from_secondary_analysis_files_for_sample_uuid(sample_uuid: str,
                                                                     ds_files: dict,
                                                                     spatial_url: str) -> None:
    """Task to aggregate the cell type counts and send them back to Spatial-Api"""
    logger.info(f'Extract Cell Count Job; sample_uuid:{sample_uuid}, ds_files: {ds_files}, spatial_url: {spatial_url}')
    url = f"{spatial_url}/samples/cell-type-counts"
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
    logger.info(f'URL: {url} DATA: {data}')
    # Send the data that it time-consuming to produce, spacial-api will finish up with this but respond back
    # to us that it is simply "working on it". There is no loop to close here. Status checked just to log it.
    resp: Response = requests.put(url, headers=headers, data=json.dumps(data))
    if resp.status_code == 202:
        logger.info(f'Received expected 202 status from {url} while processing sample {sample_uuid}')
    else:
        logger.error(f'Unexpected response ({resp.status_code}) for {url} while processing sample {sample_uuid}')

