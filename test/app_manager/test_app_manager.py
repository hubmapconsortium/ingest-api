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

    def test_groups_token_from_request_headers(self):
        result = app_manager.groups_token_from_request_headers(self.request_headers)

        self.assertEqual(result, self.token)

if __name__ == "__main__":
    import nose2
    nose2.main()
