import os
import unittest
from pyfakefs.fake_filesystem_unittest import TestCase
import logging
import requests
from unittest.mock import Mock, patch

# Local modules
from app_manager import handle_thumbnail_file
from api.entity_api import EntityApi

logger = logging.getLogger(__name__)

#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
# 
# Use test classes derived from fake_filesystem_unittest.TestCase
class TestDatasetThumbnail(TestCase):

    def setUp(self):
        # pyfakefs will automatically find all real file functions and modules, 
        # and stub these out with the fake file system functions and modules
        self.setUpPyfakefs()

        self.token = 'token'
        self.entity_api_url = 'entity_api_url'

    @patch('app_manager.EntityApi.get_entities')
    @patch('app_manager.EntityApi.put_entities')
    def test_dataset_thumbnail_file_handling(self, mock_get_entities, mock_put_entities):
        dataset_dict = {'thumbnail_file_abs_path': '/hive/hubmap/data/public/University of Florida TMC/e69fb303e035192a0ee38a34e4b25024/extra/thumbnail.jpg'}
        entity_api = EntityApi(self.token, self.entity_api_url)
        dataset_uuid = 'e69fb303e035192a0ee38a34e4b25024'
        temp_file_id = '40bc92d7eb4a77988f274f2e6862d42a'
        file_upload_temp_dir = '/hive/hubmap/hm_uploads_tmp'
        extra_headers = {
            'Content-Type': 'application/json', 
            'X-Hubmap-Application': 'ingest-api'
        }

        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'thumbnail_file': {'filename': 'thumbnail.jpg', 'file_uuid': 'fc95dd0faaf2cfc4786d89bf7b074485'}}
            return r
        mock_get_entities.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {}
            return r
        mock_put_entities.side_effect = [resp2()]

        file_path = '/hive/hubmap/data/public/University of Florida TMC/e69fb303e035192a0ee38a34e4b25024/extra/thumbnail.jpg'
        self.assertFalse(os.path.exists(file_path))
        self.fs.create_file(file_path)
        self.assertTrue(os.path.exists(file_path))

        updated_dataset_dict = handle_thumbnail_file(dataset_dict,
                                                     entity_api,
                                                     dataset_uuid, 
                                                     extra_headers, 
                                                     temp_file_id, 
                                                     file_upload_temp_dir)

        logger.debug(updated_dataset_dict)

        self.assertFalse('thumbnail_file_abs_path' in updated_dataset_dict)
        self.assertTrue('thumbnail_file_to_add' in updated_dataset_dict)

if __name__ == "__main__":
    import nose2
    nose2.main()
