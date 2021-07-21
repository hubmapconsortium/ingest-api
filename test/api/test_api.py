import unittest
from unittest.mock import patch

import requests
from api.api import Api


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestApi(unittest.TestCase):

    def setUp(self):
        self.bearer_token = 'NiceToken'
        self.api_url = 'http://www.kollar.com/'
        self.api = Api(self.bearer_token, self.api_url)

    @patch('api.api.requests.get')
    def test_create_dataset_draft_doi_happy_path(self, mock_get):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_get.side_effect = [resp1()]

        path = "happy_goat.html"
        self.api.request_get(path)

        mock_get.assert_called()
        args = mock_get.call_args_list[-1]

        url_from_get_call = args[1]['url']
        self.assertEqual(url_from_get_call, f"{self.api_url}{path}")

        headers_from_get_call = args[1]['headers']
        self.assertTrue('Authorization' in headers_from_get_call)
        self.assertEqual(headers_from_get_call['Authorization'], f"Bearer {self.bearer_token}")
        self.assertTrue('Content-Type' in headers_from_get_call)
        self.assertEqual(headers_from_get_call['Content-Type'], 'application/json')

        headers_from_get_call = args[1]['verify']
        self.assertFalse(headers_from_get_call)
