import unittest

from app_manager import AppManager
from unittest.mock import Mock, MagicMock
from dataset import Dataset
from src.dataset_helper_object import DatasetHelper

#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestAppManager(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.logger.info = MagicMock(name='info', return_value=None)

        self.dataset_helper = DatasetHelper
        self.dataset_helper.__init__ = MagicMock(name='__init__', return_value=None)
        self.dataset_helper.generate_dataset_title = MagicMock(spec='generate_dataset_title', return_value='Dataset Title String')

        self.request_json = []
        self.request_headers = {'AUTHORIZATION': 'bearer   token'}

        self.dataset = Dataset
        self.dataset.__init__ = MagicMock(name='__init__', return_value=None)
        self.dataset.get_dataset_ingest_update_record = MagicMock(name='get_dataset_ingest_update_record')

        self.app_manager = AppManager()

    def test_update_ingest_status_with_status_qa(self):
        self.dataset.get_dataset_ingest_update_record.return_value = {
            'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a',
            'status' : 'QA',
            'message' : 'the process ran'
        }

        result = self.app_manager.update_ingest_status(None, self.request_json, self.request_headers, self.logger)

        self.assertTrue('title' in result)
        self.assertEqual(result['title'], 'Dataset Title String')
        self.assertEqual(len(result), 4)

    def test_update_ingest_status_with_not_status_qa(self):
        self.dataset.get_dataset_ingest_update_record.return_value = {
            'dataset_id': '287d61b60b806fdf54916e3b7795ad5a',
            'status': 'Unknown',
            'message': 'the process ran'
        }

        result = self.app_manager.update_ingest_status(None, self.request_json, self.request_headers, self.logger)

        self.assertFalse('title' in result)
        self.dataset_helper.generate_dataset_title.assert_not_called()
        self.assertEqual(len(result), 3)


if __name__ == "__main__":
    import nose2
    nose2.main()
