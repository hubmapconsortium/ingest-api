from flask import current_app
import urllib.request
from hubmap_commons import file_helper as commons_file_helper


def get_globus_url(data_access_level, group_name, uuid):
    globus_server_uuid = None
    dir_path = ""
    # public access
    if data_access_level == "public":
        globus_server_uuid = current_app.config['GLOBUS_PUBLIC_ENDPOINT_UUID']
        access_dir = commons_file_helper.ensureTrailingSlashURL(current_app.config['RELATIVE_GLOBUS_PUBLIC_ENDPOINT_FILEPATH'])
        dir_path = dir_path + access_dir + "/"
    # consortium access
    elif data_access_level == 'consortium':
        globus_server_uuid = current_app.config['GLOBUS_CONSORTIUM_ENDPOINT_UUID']
        access_dir = commons_file_helper.ensureTrailingSlashURL(current_app.config['RELATIVE_GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH'])
        dir_path = dir_path + access_dir + group_name + "/"
    # protected access
    elif data_access_level == 'protected':
        globus_server_uuid = current_app.config['GLOBUS_PROTECTED_ENDPOINT_UUID']
        access_dir = commons_file_helper.ensureTrailingSlashURL(current_app.config['RELATIVE_GLOBUS_PROTECTED_ENDPOINT_FILEPATH'])
        dir_path = dir_path + access_dir + group_name + "/"

    if globus_server_uuid is not None:
        dir_path = dir_path + uuid + "/"
        dir_path = urllib.parse.quote(dir_path, safe='')

        # https://current_app.globus.org/file-manager?origin_id=28bb03c-a87d-4dd7-a661-7ea2fb6ea631&origin_path=2%FIEC%20Testing%20Group%20F03584b3d0f8b46de1b29f04be1568779%2F
        globus_url = commons_file_helper.ensureTrailingSlash(current_app.config[
                                                                 'GLOBUS_APP_BASE_URL']) + "file-manager?origin_id=" + globus_server_uuid + "&origin_path=" + dir_path
    else:
        globus_url = ""
    if uuid is None:
        globus_url = ""
    return globus_url
