import unittest
from unittest.mock import patch

from api.search_api import SearchApi


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestSearchApi(unittest.TestCase):

    def setUp(self):
        self.bearer_token = 'NiceToken'
        self.api_url = 'http://www.kollar.com/'
        self.search_api = SearchApi(self.bearer_token, self.api_url)

    @patch('api.api.Api.request_get_public')
    def test_get_assaytype(self, mock_request_get_public):

        data_type = "nice_data_type"
        self.search_api.get_assaytype(data_type)

        mock_request_get_public.assert_called()
        args = mock_request_get_public.call_args_list[0]
        self.assertEqual(args[0][0], f"assaytype/{data_type}")
