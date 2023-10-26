import csv
import os
import logging
from hubmap_commons import file_helper as commons_file_helper
from flask import current_app, request
from atlas_consortia_commons.rest import *
from werkzeug import utils
from collections import OrderedDict
from lib.file_upload_helper import UploadFileHelper

logger = logging.getLogger(__name__)


def get_csv_records(path: str, records_as_arr = False, is_ordered = False):
    records = []
    headers = []
    with open(path, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            if records_as_arr is True:
                data_row = []
                for key in row.keys():
                    if first:
                        headers.append(key)
                    data_row.append(row[key])
            else:
                data_row = OrderedDict() if is_ordered is True else {}
                for key in row.keys():
                    if first:
                        headers.append(key)
                    data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False

    return {
        'records': records,
        'headers': headers
    }


def get_base_path():
    return commons_file_helper.ensureTrailingSlash(current_app.config['FILE_UPLOAD_TEMP_DIR'])


def check_upload(key: str = 'file'):
    try:
        if not UploadFileHelper.is_initialized():
            file_upload_helper_instance = UploadFileHelper.create(current_app.config['FILE_UPLOAD_TEMP_DIR'],
                                                                  current_app.config['FILE_UPLOAD_DIR'],
                                                                  current_app.config['UUID_WEBSERVICE_URL'])
            logger.info('Initialized UploadFileHelper class successfully :)')
        else:
            file_upload_helper_instance = UploadFileHelper.instance()

        if key not in request.files:
            abort_bad_req('No file part')

        file = request.files[key]
        if file.filename == '':
            abort_bad_req('No selected file')

        file.filename = file.filename.replace(' ', '_')
        temp_id = file_upload_helper_instance.save_temp_file(file)
        file.filename = utils.secure_filename(file.filename)

        return rest_response(StatusCodes.OK, 'OK', {
            'id': temp_id,
            'file': file
        }, True)

    except Exception as e:
        if hasattr(e, 'code'):
            return rest_response(e.code, e.name, e.description, True)
        else:
            return rest_server_err(e, True)


def ln_err(error: str, row: int = None, column: str = None):
    return {
        'column': column,
        'error': error,
        'row': row
    }


def files_exist(uuid, data_access_level, group_name):
    if not uuid or not data_access_level:
        return False
    if data_access_level == "public":
        absolute_path = commons_file_helper.ensureTrailingSlashURL(current_app.config['GLOBUS_PUBLIC_ENDPOINT_FILEPATH'])
    # consortium access
    elif data_access_level == 'consortium':
        absolute_path = commons_file_helper.ensureTrailingSlashURL(current_app.config['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH'] + '/' + group_name)
    # protected access
    elif data_access_level == 'protected':
        absolute_path = commons_file_helper.ensureTrailingSlashURL(current_app.config['GLOBUS_PROTECTED_ENDPOINT_FILEPATH'] + '/' + group_name)
    file_path = absolute_path + uuid
    if os.path.exists(file_path) and os.path.isdir(file_path) and os.listdir(file_path):
        return True
    else:
        return False
