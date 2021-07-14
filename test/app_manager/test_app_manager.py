import unittest
import requests
import app_manager
from unittest.mock import MagicMock
from dataset import Dataset
from dataset_helper_object import DatasetHelper

#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestAppManager(unittest.TestCase):

    def setUp(self):
        self.token = 'token'
        self.request_headers = {'AUTHORIZATION': f'bearer   {self.token}'}

    def test_nexus_token_from_request_headers(self):
        result = app_manager.nexus_token_from_request_headers(self.request_headers)

        self.assertEqual(result, self.token)

    def update_ingest_status_with_status_qa(self):
        self.dataset.get_dataset_ingest_update_record.return_value = {
            'dataset_id': '287d61b60b806fdf54916e3b7795ad5a',
            'status': 'QA',
            'message': 'the process ran'
        }

        result = app_manager.update_ingest_status_title_thumbnail(None, 
                                                                  self.request_json, 
                                                                  self.request_headers, 
                                                                  MagicMock(),
                                                                  MagicMock())

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

        result = app_manager.update_ingest_status_title_thumbnail(None, 
                                                                  self.request_json, 
                                                                  self.request_headers, 
                                                                  MagicMock(),
                                                                  MagicMock())

        self.assertFalse('title' in result)
        self.dataset_helper.generate_dataset_title.assert_not_called()
        self.assertEqual(len(result), 3)

if __name__ == "__main__":
    import nose2
    nose2.main()
