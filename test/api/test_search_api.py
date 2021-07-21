import unittest
from unittest.mock import patch

import requests
from api.search_api import SearchApi
import pprint


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestApi(unittest.TestCase):

    def setUp(self):
        self.bearer_token = 'NiceToken'
        self.api_url = 'http://www.kollar.com/'
        self.url_path = "happy_goat.html"
        self.search_api = SearchApi(self.bearer_token, self.api_url)

    @patch('api.api.requests.get')
    def test_get_assaytype(self, mock_get):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_get.side_effect = [resp1()]

        data_type = "nice_data_type"
        self.search_api.get_assaytype(data_type)

        mock_get.assert_called()
        args = mock_get.call_args_list[-1]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}/assaytype/{data_type}")

        self.assertFalse('headers' in args[1])

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])