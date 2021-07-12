import unittest
import requests
from app_manager import update_ingest_status, nexus_token_from_request_headers, handle_thumbnail_file
from unittest.mock import Mock, MagicMock, patch
from dataset import Dataset
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi

import logging
logger = logging.getLogger(__name__)

#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestAppManager(unittest.TestCase):

    def setUp(self):
        self.token = 'token'
        self.request_headers = {'AUTHORIZATION': f'bearer   {self.token}'}

        self.entity_api_url = 'entity_api_url'

        #
        # self.dataset_helper = DatasetHelper
        # self.dataset_helper.__init__ = MagicMock(name='__init__', return_value=None)
        # self.dataset_helper.generate_dataset_title = \
        #     MagicMock(spec='generate_dataset_title', return_value='Dataset Title String')
        #
        # self.request_json = []
        #
        # self.dataset = Dataset
        # self.dataset.__init__ = MagicMock(name='__init__', return_value=None)
        # self.dataset.get_dataset_ingest_update_record = MagicMock(name='get_dataset_ingest_update_record')

    def test_nexus_token_from_request_headers(self):
        result = nexus_token_from_request_headers(self.request_headers)

        self.assertEqual(result, self.token)

    def update_ingest_status_with_status_qa(self):
        self.dataset.get_dataset_ingest_update_record.return_value = {
            'dataset_id': '287d61b60b806fdf54916e3b7795ad5a',
            'status': 'QA',
            'message': 'the process ran'
        }
        
        result = update_ingest_status(None, self.request_json, self.request_headers)

        self.assertTrue('title' in result)
        self.assertEqual(result['title'], 'Dataset Title String')
        self.dataset_helper.generate_dataset_title.assert_called()
        self.assertEqual(len(result), 4)

    def update_ingest_status_with_not_status_qa(self):
        self.dataset.get_dataset_ingest_update_record.return_value = {
            'dataset_id': '287d61b60b806fdf54916e3b7795ad5a',
            'status': 'Unknown',
            'message': 'the process ran'
        }

        result = update_ingest_status(None, self.request_json, self.request_headers)

        self.assertFalse('title' in result)
        self.dataset_helper.generate_dataset_title.assert_not_called()
        self.assertEqual(len(result), 3)

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
