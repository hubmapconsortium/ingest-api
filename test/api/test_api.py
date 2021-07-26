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
        self.url_path = "happy_goat.html"
        self.api = Api(self.bearer_token, self.api_url)

    def test_add_extra_headers_with(self):
        headers = self.api.add_extra_headers({'extra_header': 'value'})

        self.assertEqual(len(headers.keys()), 2)
        self.assertTrue('Authorization' in headers)
        self.assertEqual(headers['Authorization'], f"Bearer {self.bearer_token}")
        self.assertTrue('extra_header' in headers)
        self.assertEqual(headers['extra_header'], 'value')

    def test_add_extra_headers_without(self):
        headers = self.api.add_extra_headers({})

        self.assertEqual(len(headers.keys()), 1)
        self.assertTrue('Authorization' in headers)
        self.assertEqual(headers['Authorization'], f"Bearer {self.bearer_token}")
        self.assertFalse('extra_header' in headers)

    @patch('api.api.requests.get')
    def test_request_get(self, mock_get):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_get.side_effect = [resp1()]

        self.api.request_get(self.url_path)

        mock_get.assert_called()
        args = mock_get.call_args_list[-1]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}{self.url_path}")

        self.assertTrue('headers' in args[1])
        headers_from_call = args[1]['headers']
        self.assertEqual(len(headers_from_call.keys()), 1)
        self.assertTrue('Authorization' in headers_from_call)
        self.assertEqual(headers_from_call['Authorization'], f"Bearer {self.bearer_token}")

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])

    @patch('api.api.requests.get')
    def test_request_get_public(self, mock_get):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_get.side_effect = [resp1()]

        self.api.request_get_public(self.url_path)

        mock_get.assert_called()
        args = mock_get.call_args_list[0]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}{self.url_path}")

        self.assertFalse('headers' in args[1])

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])

    @patch('api.api.requests.post')
    def test_request_post(self, mock_post):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_post.side_effect = [resp1()]

        json = {'test': 'value'}

        self.api.request_post(self.url_path, json)

        mock_post.assert_called()
        args = mock_post.call_args_list[-1]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}{self.url_path}")

        self.assertTrue('json' in args[1])
        self.assertEqual(args[1]['json'], json)

        self.assertTrue('headers' in args[1])
        headers_from_call = args[1]['headers']
        self.assertEqual(len(headers_from_call.keys()), 1)
        self.assertTrue('Authorization' in headers_from_call)
        self.assertEqual(headers_from_call['Authorization'], f"Bearer {self.bearer_token}")

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])

    @patch('api.api.requests.post')
    def test_request_post_extra_headers(self, mock_post):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_post.side_effect = [resp1()]

        json = {'test': 'value'}

        self.api.request_post(self.url_path, json, {'extra_header': 'value'})

        mock_post.assert_called()
        args = mock_post.call_args_list[-1]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}{self.url_path}")

        self.assertTrue('json' in args[1])
        self.assertEqual(args[1]['json'], json)

        self.assertTrue('headers' in args[1])
        headers_from_call = args[1]['headers']
        self.assertEqual(len(headers_from_call.keys()), 2)
        self.assertTrue('Authorization' in headers_from_call)
        self.assertEqual(headers_from_call['Authorization'], f"Bearer {self.bearer_token}")
        self.assertTrue('extra_header' in headers_from_call)
        self.assertEqual(headers_from_call['extra_header'], 'value')

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])

    @patch('api.api.requests.put')
    def test_request_put(self, mock_put):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_put.side_effect = [resp1()]

        json = {'test': 'value'}

        self.api.request_put(self.url_path, json)

        mock_put.assert_called()
        args = mock_put.call_args_list[-1]

        self.assertTrue('url' in args[1])
        self.assertEqual(args[1]['url'], f"{self.api_url}{self.url_path}")

        self.assertTrue('json' in args[1])
        self.assertEqual(args[1]['json'], json)

        self.assertTrue('headers' in args[1])
        headers_from_call = args[1]['headers']
        self.assertEqual(len(headers_from_call.keys()), 1)
        self.assertTrue('Authorization' in headers_from_call)
        self.assertEqual(headers_from_call['Authorization'], f"Bearer {self.bearer_token}")

        self.assertTrue('verify' in args[1])
        self.assertFalse(args[1]['verify'])