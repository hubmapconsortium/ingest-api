import unittest
from unittest.mock import patch

import requests

from datacite_doi_helper_object import DataCiteDoiHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestDataciteDoiHelperObject(unittest.TestCase):

    @patch("datacite_doi_helper_object.load_flask_instance_config")
    def setUp(self, mock_load_flask_instance_config):
        mock_load_flask_instance_config.return_value =\
            {'DATACITE_API_URL': 'eUrl', 'DATACITE_REPOSITORY_ID': 'PSC.HUBMAP',
             'DATACITE_REPOSITORY_PASSWORD': 'xyzzy', 'ENTITY_WEBSERVICE_URL': 'sUrl',
             'DATACITE_HUBMAP_PREFIX': '10.80478'}
        self.datacite_doi_helper = DataCiteDoiHelper()
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.dataset = {'uuid': self.dataset_uuid, 'entity_type': 'Dataset', 'hubmap_id': 'Hubmap ID'}
        self.response_doi = {'data': {'id': 'HBM836.LNMM.773', 'type': 'dois', 'attributes': {'doi': '10.80478/HBM836.LNMM.773', 'creators': [{'name': 'HuBMAP'}], 'titles': [{'title': 'sciATAC-seq data from the heart of a 25-year-old white female'}], 'publisher': 'HuBMAP Consortium', 'publicationYear': 2021, 'types': {'resourceTypeGeneral': 'Dataset'}, 'url': 'https://entity-api.test.hubmapconsortium.org/doi/redirect/2d4d2f368c6f74cc3aa17177924003b8'}}}

    @patch('datacite_doi_helper_object.DataCiteApi.post_create_draft_doi')
    def test_create_dataset_draft_doi_happy_path(self, mock_post_create_draft_doi):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: self.response_doi
            return r
        mock_post_create_draft_doi.side_effect = [resp1()]

        doi_data = self.datacite_doi_helper.create_dataset_draft_doi(self.dataset, "Dataset Title String")

        mock_post_create_draft_doi.assert_called()
        self.assertEqual(doi_data, self.response_doi)

    @patch('datacite_doi_helper_object.DataCiteApi.post_create_draft_doi')
    def test_create_dataset_draft_doi_fail(self, mock_post_create_draft_doi):
        def resp1():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_post_create_draft_doi.side_effect = [resp1()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.create_dataset_draft_doi, self.dataset, "Dataset Title String")
        mock_post_create_draft_doi.assert_called()

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.put_publish_doi')
    def test_move_doi_state_from_draft_to_findable_happy_path(self, mock_put_publish_doi, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_put_publish_doi.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_put_entities.side_effect = [resp2()]

        doi_data = self.datacite_doi_helper.move_doi_state_from_draft_to_findable(self.dataset, "User Token String")

        mock_put_publish_doi.assert_called()
        mock_put_entities.assert_called()
        self.assertEqual(doi_data, self.response_doi)

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.put_publish_doi')
    def test_move_doi_state_from_draft_to_findable_fail1(self, mock_put_publish_doi, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_put_publish_doi.side_effect = [resp1()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.move_doi_state_from_draft_to_findable, self.dataset, "Dataset Title String")
        mock_put_publish_doi.assert_called()
        mock_put_entities.assert_not_called()

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.put_publish_doi')
    def test_move_doi_state_from_draft_to_findable_fail2(self, mock_put_publish_doi, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_put_publish_doi.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_put_entities.side_effect = [resp2()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.move_doi_state_from_draft_to_findable, self.dataset, "Dataset Title String")
        mock_put_publish_doi.assert_called()
        mock_put_entities.assert_called()