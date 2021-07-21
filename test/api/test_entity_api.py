import unittest
from unittest.mock import patch

import requests
from api.entity_api import EntityApi


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestEntityApi(unittest.TestCase):

    def setUp(self):
        self.bearer_token = 'NiceToken'
        self.api_url = 'http://www.kollar.com/'
        self.entity_api = EntityApi(self.bearer_token, self.api_url)

    @patch('api.api.Api.request_post')
    def test_post_entities(self, mock_request_post):

        dataset_uuid = "nice_uuid"
        json = {'test': 'value'}
        self.entity_api.post_entities(dataset_uuid, json, None)

        mock_request_post.assert_called()
        args = mock_request_post.call_args_list[0]
        self.assertEqual(args[0][0], f"/entities/{dataset_uuid}")
        self.assertEqual(args[0][1], json)
        self.assertEqual(args[0][2], None)

    @patch('api.api.Api.request_put')
    def test_put_entities(self, mock_request_put):

        dataset_uuid = "nice_uuid"
        json = {'test': 'value'}
        self.entity_api.put_entities(dataset_uuid, json, None)

        mock_request_put.assert_called()
        args = mock_request_put.call_args_list[0]
        self.assertEqual(args[0][0], f"/entities/{dataset_uuid}")
        self.assertEqual(args[0][1], json)
        self.assertEqual(args[0][2], None)

    @patch('api.api.Api.request_get')
    def test_get_entities(self, mock_request_get):

        dataset_uuid = "nice_uuid"
        self.entity_api.get_entities(dataset_uuid)

        mock_request_get.assert_called()
        args = mock_request_get.call_args_list[0]
        self.assertEqual(args[0][0], f"/entities/{dataset_uuid}")

    @patch('api.api.Api.request_get')
    def test_get_ancestors(self, mock_request_get):

        dataset_uuid = "nice_uuid"
        self.entity_api.get_ancestors(dataset_uuid)

        mock_request_get.assert_called()
        args = mock_request_get.call_args_list[0]
        self.assertEqual(args[0][0], f"/ancestors/{dataset_uuid}")