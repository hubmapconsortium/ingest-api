from flask import Blueprint, jsonify, request, current_app
from shutil import rmtree
from pathlib import Path
import os
import logging

from file_upload_helper import UploadFileHelper
from app_utils.request_validation import require_json
from app_utils.error import internal_server_error, bad_request_error

file_blueprint = Blueprint('file', __name__)
logger: logging.Logger = logging.getLogger(__name__)


"""
File upload handling for Donor and Sample

Returns
-------
json
    A JSON containing the temp file id
"""
@file_blueprint.route('/file-upload', methods=['POST'])
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        bad_request_error('No file part')

    file = request.files['file']

    if file.filename == '':
        bad_request_error('No selected file')

    try:
        file_upload_helper_instance = UploadFileHelper.instance()
        temp_id = file_upload_helper_instance.save_temp_file(file)
        rspn_data = {
            "temp_file_id": temp_id
        }

        return jsonify(rspn_data), 201
    except Exception as e:
        # Log the full stack trace, prepend a line with our message
        msg = "Failed to upload files"
        logger.exception(msg)
        internal_server_error(msg)

"""
File commit triggered by entity-api trigger method for Donor/Sample/Dataset

Donor: image files
Sample: image files and metadata files
Dataset: only the one thumbnail file

This call also creates the symbolic from the file uuid dir under uploads
to the assets dir so the uploaded files can be exposed via gateway's file assets service

Returns
-------
json
    A JSON containing the file uuid info
"""
@file_blueprint.route('/file-commit', methods=['POST'])
def commit_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    temp_file_id = json_data_dict['temp_file_id']
    entity_uuid = json_data_dict['entity_uuid']
    user_token = json_data_dict['user_token']

    file_upload_helper_instance = UploadFileHelper.instance()
    file_uuid_info = file_upload_helper_instance.commit_file(temp_file_id, entity_uuid, user_token)
    filename = file_uuid_info['filename']
    file_uuid = file_uuid_info['file_uuid']

    # Link the uploaded file uuid dir to assets
    # /hive/hubmap/hm_uploads/<entity_uuid>/<file_uuid>/<filename> (for PROD)
    source_file_path = os.path.join(str(current_app.config['FILE_UPLOAD_DIR']), entity_uuid, file_uuid, filename)
    # /hive/hubmap/assets/<file_uuid>/<filename> (for PROD)
    target_file_dir = os.path.join(str(current_app.config['HUBMAP_WEBSERVICE_FILEPATH']), file_uuid)
    target_file_path = os.path.join(target_file_dir, filename)

    # Create the file_uuid directory under assets dir
    # and a symbolic link to the uploaded file
    try:
        Path(target_file_dir).mkdir(parents=True, exist_ok=True)
        os.symlink(source_file_path, target_file_path)
    except Exception as e:
        logger.exception(f"Failed to create the symbolic link from {source_file_path} to {target_file_path}")

    # Send back the updated file_uuid_info
    return jsonify(file_uuid_info)

"""
File removal triggered by entity-api trigger method for Donor/Sample/Dataset
during entity update

Donor: image files
Sample: image files and metadata files
Dataset: only the one thumbnail file

Returns
-------
json
    A JSON list containing the updated files info
    It's an empty list for Dataset since there's only one thumbnail file
"""
@file_blueprint.route('/file-remove', methods=['POST'])
def remove_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    entity_uuid = json_data_dict['entity_uuid']
    file_uuids = json_data_dict['file_uuids']
    files_info_list = json_data_dict['files_info_list']

    file_upload_helper_instance = UploadFileHelper.instance()
    # `upload_dir` is already normalized with trailing slash
    entity_upload_dir = file_upload_helper_instance.upload_dir + entity_uuid + os.sep

    # Remove the physical files from the file system
    for file_uuid in file_uuids:
        # Get back the updated files_info_list
        files_info_list = file_upload_helper_instance.remove_file(entity_upload_dir, file_uuid, files_info_list)

        # Also remove the dir contains the symlink to the uploaded file under assets
        # /hive/hubmap/assets/<file_uuid> (for PROD)
        assets_file_dir = os.path.join(str(current_app.config['HUBMAP_WEBSERVICE_FILEPATH']), file_uuid)
        # Delete an entire directory tree
        # path must point to a directory (but not a symbolic link to a directory)
        rmtree(assets_file_dir)

    # Send back the updated files_info_list
    return jsonify(files_info_list)
