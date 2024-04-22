import os
import logging
from hubmap_commons.hm_auth import AuthHelper


class IngestFileHelper:

    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger('ingest.service')

    def get_dataset_directory_absolute_path(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = self.appconfig['ACCESS_LEVEL_PROTECTED']
        elif not 'data_access_level' in dataset_record:
            access_level = self.appconfig['ACCESS_LEVEL_CONSORTIUM']
        else:
            access_level = dataset_record['data_access_level']

        published = False
        if 'status' in dataset_record and dataset_record['status'] == 'Published':
            published = True

        return self.dataset_directory_absolute_path(access_level, group_uuid, dataset_uuid, published)

    def dataset_directory_absolute_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == 'protected':
            base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        elif published:
            base_dir = self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, dataset_uuid))
        else:
            base_dir = self.appconfig['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))

        return abs_path
