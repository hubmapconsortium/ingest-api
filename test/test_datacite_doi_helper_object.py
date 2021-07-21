import unittest
from unittest.mock import patch
#import pprint

import requests

from datacite_doi_helper_object import DataCiteDoiHelper
from api.datacite_api import DataCiteApi
from datetime import datetime


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestDataciteDoiHelperObject(unittest.TestCase):

    @patch("datacite_doi_helper_object.load_flask_instance_config")
    def setUp(self, mock_load_flask_instance_config):
        self.hubmap_prefix = '10.80478'
        self.datacite_api_url = 'eUrl'
        self.entity_webservice_url = 'sUrl'
        mock_load_flask_instance_config.return_value =\
            {'DATACITE_API_URL': self.datacite_api_url, 'DATACITE_REPOSITORY_ID': 'PSC.HUBMAP',
             'DATACITE_REPOSITORY_PASSWORD': 'xyzzy', 'ENTITY_WEBSERVICE_URL': self.entity_webservice_url,
             'DATACITE_HUBMAP_PREFIX': self.hubmap_prefix}
        self.datacite_doi_helper = DataCiteDoiHelper()

        self.response_doi = {'data': {'id': 'HBM836.LNMM.773', 'type': 'dois', 'attributes': {'doi': '10.80478/HBM836.LNMM.773', 'creators': [{'name': 'HuBMAP'}], 'titles': [{'title': 'sciATAC-seq data from the heart of a 25-year-old white female'}], 'publisher': 'HuBMAP Consortium', 'publicationYear': 2021, 'types': {'resourceTypeGeneral': 'Dataset'}, 'url': 'https://entity-api.test.hubmapconsortium.org/doi/redirect/2d4d2f368c6f74cc3aa17177924003b8'}}}
        self.hubmap_id = "HBM627.RSGW.898"
        self.uuid = "8690897fced9931da34d66d669c1d698"
        # The 'dataset' below is from this query to find datasets where any contributor is a contact:
        # match (ds:Dataset) where ds.contributors contains "is_contact" return ds
        # So, it's a REAL dataset entry that would be used by the method that we are testing!!!
        self.dataset = {
            "ingest_metadata": "{'dag_provenance_list': [{'hash': '60af1dc', 'origin': 'https://github.com/hubmapconsortium/ingest-pipeline.git'}], 'metadata': {'acquisition_instrument_model': 'SCN-400', 'acquisition_instrument_vendor': 'Leica ', 'analyte_class': 'polysaccharides', 'assay_category': 'imaging', 'assay_type': 'PAS microscopy', 'contributors_path': 'extras/contributers.tsv', 'data_path': '.', 'description': 'Periodic acid-Schiff stained microscopy collected from the right kidney of a 66 year old White male donor by the Biomolecular Multimodal Imaging Center (BIOMC) at Vanderbilt University. BIOMIC is a Tissue Mapping Center that is part of the NIH funded Human Biomolecular Atlas Program (HuBMAP). Brightfield microscopy images of formalin-fixed paraffin-embedded (FFPE) tissue sections were collected with a Leica BioSystems SCN-400. Support was provided by the NIH Common Fund and National Institute of Diabetes and Digestive and Kidney Diseases (U54 DK120058). Tissue was collected through the Cooperative Human Tissue Network with support provided by the NIH National Cancer Institute (5 UM1 CA183727-08).', 'donor_id': 'VAN0032', 'execution_datetime': '2020-09-10 18:27', 'is_targeted': 'False', 'operator': 'Elizabeth K. Neumann', 'operator_email': 'elizabeth.neumann@vanderbilt.edu', 'overall_protocols_io_doi': '10.17504/protocols.io.bfskjncw', 'pi': 'Jeffrey M. Spraggins', 'pi_email': 'jeff.spraggins@vanderbilt.edu', 'protocols_io_doi': '10.17504/protocols.io.buaknscw', 'resolution_x_unit': 'um', 'resolution_x_value': '0.65', 'resolution_y_unit': 'um', 'resolution_y_value': '0.65', 'resolution_z_unit': 'um', 'resolution_z_value': '0', 'section_prep_protocols_io_doi': '10.17504/protocols.io.bt8inrue', 'stain': 'Periodic acid-Schiff', 'tissue_id': 'VAN0032-RK-5-6', 'version': '1'}, 'extra_metadata': {'collectiontype': 'generic_metadatatsv'}}",
            "last_modified_timestamp": 1621538119292,
            "description": "Periodic acid-Schiff stained microscopy collected from the right kidney of a 66 year old White male donor by the Biomolecular Multimodal Imaging Center (BIOMC) at Vanderbilt University. BIOMIC is a Tissue Mapping Center that is part of the NIH funded Human Biomolecular Atlas Program (HuBMAP). Brightfield microscopy images of formalin-fixed paraffin-embedded (FFPE) tissue sections were collected with a Leica BioSystems SCN-400. Support was provided by the NIH Common Fund and National Institute of Diabetes and Digestive and Kidney Diseases (U54 DK120058). Tissue was collected through the Cooperative Human Tissue Network with support provided by the NIH National Cancer Institute (5 UM1 CA183727-08).",
            "group_uuid": "73bb26e4-ed43-11e8-8f19-0a7c1eab007a",
            "title": "VAN0032-RK-5-6-PAS",
            "uuid": self.uuid,
            "ingest_id": "8690897fced9931da34d66d669c1d698_scan.and.begin.processing_2021-05-15T00:01:08.033754-04:00",
            "lab_dataset_id": "VAN0032-RK-5-6-PAS",
            "last_modified_user_displayname": "HuBMAP Process",
            "published_timestamp": 1621538119292,
            "run_id": "8690897fced9931da34d66d669c1d698_scan.and.begin.processing_2021-05-15T00:01:08.033754-04:00",
            "group_name": "Vanderbilt TMC",
            "created_by_user_displayname": "Nathan Patterson",
            "created_timestamp": 1621025450230,
            "created_by_user_sub": "17d825d9-74e4-47dd-a9fa-6e5f199684a0",
            "created_by_user_email": "nathan.h.patterson@vanderbilt.edu",
            "published_user_sub": "3e7bce63-129d-33d0-8f6c-834b34cd382e",
            "entity_type": "Dataset",
            "data_access_level": "public",
            "published_user_email": "hubmap@hubmapconsortium.org",
            "hubmap_id": self.hubmap_id,
            "last_modified_user_sub": "3e7bce63-129d-33d0-8f6c-834b34cd382e",
            "last_modified_user_email": "hubmap@hubmapconsortium.org",
            "pipeline_message": "the process ran",
            "contributors": "[{'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Jamie', 'is_contact': 'FALSE', 'last_name': 'Allen', 'middle_name_or_initial': 'L.', 'name': 'Jamie L. Allen', 'orcid_id': '0000-0002-4739-2166', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'David', 'is_contact': 'FALSE', 'last_name': 'Anderson', 'middle_name_or_initial': 'M.G.', 'name': 'David M.G. Anderson', 'orcid_id': '0000-0002-3866-0923', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Maya', 'is_contact': 'FALSE', 'last_name': 'Brewer', 'middle_name_or_initial': '', 'name': 'Maya Brewer', 'orcid_id': '0000-0001-5914-0081', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Richard', 'is_contact': 'FALSE', 'last_name': 'Caprioli', 'middle_name_or_initial': 'M.', 'name': 'Richard M. Caprioli', 'orcid_id': '0000-0001-5859-3310', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Mark', 'is_contact': 'FALSE', 'last_name': 'deCaestecker', 'middle_name_or_initial': '', 'name': 'Mark deCaestecker', 'orcid_id': '0000-0001-7926-1673', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Agnes', 'is_contact': 'FALSE', 'last_name': 'Fogo', 'middle_name_or_initial': 'B.', 'name': 'Agnes B. Fogo', 'orcid_id': '0000-0003-3698-8527', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Danielle', 'is_contact': 'FALSE', 'last_name': 'Gutierrez', 'middle_name_or_initial': 'B.', 'name': 'Danielle B. Gutierrez', 'orcid_id': '0000-0001-6355-2134', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Raymond', 'is_contact': 'FALSE', 'last_name': 'Harris', 'middle_name_or_initial': 'C.', 'name': 'Raymond C. Harris', 'orcid_id': '0000-0001-8025-0883', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Jennifer', 'is_contact': 'FALSE', 'last_name': 'Harvey', 'middle_name_or_initial': '', 'name': 'Jennifer Harvey', 'orcid_id': '0000-0003-3067-1238', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Migas', 'is_contact': 'FALSE', 'last_name': 'Lukasz', 'middle_name_or_initial': '', 'name': 'Lukasz Migas', 'orcid_id': '0000-0002-1884-6405', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Elizabeth', 'is_contact': 'FALSE', 'last_name': 'Neumann', 'middle_name_or_initial': 'K.', 'name': 'Elizabeth K. Neumann', 'orcid_id': '0000-0002-6078-3321', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Nathan', 'is_contact': 'FALSE', 'last_name': 'Patterson', 'middle_name_or_initial': 'Heath', 'name': 'Nathan Heath Patterson', 'orcid_id': '0000-0002-0064-1583', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Kavya', 'is_contact': 'FALSE', 'last_name': 'Sharman', 'middle_name_or_initial': '', 'name': 'Kavya Sharman', 'orcid_id': '0000-0002-3487-7199', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Jeffrey', 'is_contact': 'TRUE', 'last_name': 'Spraggins', 'middle_name_or_initial': 'M.', 'name': 'Jeffrey M. Spraggins', 'orcid_id': '0000-0001-9198-5498', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Leonoor', 'is_contact': 'FALSE', 'last_name': 'Tideman', 'middle_name_or_initial': '', 'name': 'Leonor Tideman', 'orcid_id': '0000-0001-7405-3146', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Raf', 'is_contact': 'FALSE', 'last_name': 'Van de Plas', 'middle_name_or_initial': '', 'name': 'Raf Van de Plas', 'orcid_id': '0000-0002-2232-7130', 'version': '1'}, {'affiliation': 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA', 'first_name': 'Haichun', 'is_contact': 'FALSE', 'last_name': 'Yang', 'middle_name_or_initial': '', 'name': 'Haichun Yang', 'orcid_id': '0000-0003-4265-7492', 'version': '1'}]",
            "data_types": "['PAS']",
            "published_user_displayname": "HuBMAP Process",
            "status": "Published"
            }

    @patch('api.datacite_api.requests.post')
    def test_create_dataset_draft_doi_happy_path(self, mock_post):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r
        mock_post.side_effect = [resp1()]

        dataset_title_string = "Dataset Title String"

        self.datacite_doi_helper.create_dataset_draft_doi(self.dataset, dataset_title_string)

        mock_post.assert_called()
        args = mock_post.call_args_list[-1]

        url_from_post_call = args[1]['url']
        self.assertEqual(url_from_post_call, self.datacite_api_url)

        headers_from_post_call = args[1]['headers']
        self.assertTrue('Content-Type' in headers_from_post_call)
        self.assertEqual(headers_from_post_call['Content-Type'], 'application/vnd.api+json')

        json_from_post_call = args[1]['json']
        #pprint.pprint(json_from_post_call)
        self.assertEqual(json_from_post_call['data']['id'], self.hubmap_id)
        self.assertEqual(json_from_post_call['data']['type'], 'dois')
        self.assertEqual(json_from_post_call['data']['attributes']['event'], 'register')
        self.assertEqual(json_from_post_call['data']['attributes']['doi'], f"{self.hubmap_prefix}/{self.hubmap_id}")
        self.assertEqual(json_from_post_call['data']['attributes']['titles'][0]['title'], dataset_title_string)
        self.assertEqual(json_from_post_call['data']['attributes']['publisher'], 'HuBMAP Consortium')
        self.assertEqual(json_from_post_call['data']['attributes']['publicationYear'], int(datetime.now().year))
        self.assertEqual(json_from_post_call['data']['attributes']['types']['resourceTypeGeneral'], 'Dataset')
        self.assertEqual(json_from_post_call['data']['attributes']['url'], f"{self.entity_webservice_url}/doi/redirect/{self.uuid}")

        contributors = json_from_post_call['data']['attributes']['contributors']
        self.assertTrue(isinstance(contributors, list))
        self.assertEquals(len(contributors), 1)
        # See: https://support.datacite.org/docs/schema-40#table-3-expanded-datacite-mandatory-properties
        self.assertEquals(contributors[0]['familyName'], 'Spraggins')
        self.assertEquals(contributors[0]['givenName'], 'Jeffrey M.')
        self.assertEquals(contributors[0]['name'], 'Jeffrey M. Spraggins')
        self.assertEquals(contributors[0]['affiliation'], 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA')
        contributors0NmeIdentifiers0 = contributors[0]['nameIdentifiers']
        self.assertEquals(len(contributors0NmeIdentifiers0), 1)
        self.assertEquals(contributors0NmeIdentifiers0[0]['nameIdentifierScheme'], 'ORCID')
        self.assertEquals(contributors0NmeIdentifiers0[0]['nameIdentifier'], '0000-0001-9198-5498')
        self.assertEquals(contributors0NmeIdentifiers0[0]['schemeURI'], 'http://orchid.org')

        creators = json_from_post_call['data']['attributes']['creators']
        self.assertTrue(isinstance(creators, list))
        self.assertEquals(len(creators), 17)
        self.assertEquals(creators[0]['familyName'], 'Allen')
        self.assertEquals(creators[0]['givenName'], 'Jamie L.')
        self.assertEquals(creators[0]['name'], 'Jamie L. Allen')
        # Here there can be an array of affiliations...
        self.assertEquals(creators[0]['affiliation'][0]['name'], 'Biomolecular Multimodal Imaging Center, Vanderbilt University, Nashville, TN 37232 USA')
        creators0NmeIdentifiers0 = creators[0]['nameIdentifiers']
        self.assertEquals(len(creators0NmeIdentifiers0), 1)
        self.assertEquals(creators0NmeIdentifiers0[0]['nameIdentifierScheme'], 'ORCID')
        self.assertEquals(creators0NmeIdentifiers0[0]['nameIdentifier'], '0000-0002-4739-2166')
        self.assertEquals(creators0NmeIdentifiers0[0]['schemeURI'], 'http://orchid.org')

    @patch('api.datacite_api.requests.put')
    def test_update_doi_event_publish_happy_path(self, mock_put):
        def resp1():
            r = requests.Response()
            r.status_code = 201
            r.json = lambda: None
            return r

        mock_put.side_effect = [resp1()]

        datacite_api = DataCiteApi('PSC.HUBMAP', 'xyzzy', self.hubmap_prefix, self.datacite_api_url, 'eUrl')
        datacite_api.update_doi_event_publish(self.hubmap_id)

        mock_put.assert_called()
        args = mock_put.call_args_list[-1]

        url_from_put_call = args[1]['url']
        self.assertEqual(url_from_put_call, f"{self.datacite_api_url}/{self.hubmap_prefix}/{self.hubmap_id}")

        headers_from_put_call = args[1]['headers']
        self.assertTrue('Content-Type' in headers_from_put_call)
        self.assertEqual(headers_from_put_call['Content-Type'], 'application/vnd.api+json')

        json_from_put_call = args[1]['json']
        self.assertEqual(json_from_put_call['data']['id'], f"{self.hubmap_prefix}/{self.hubmap_id}")
        self.assertEqual(json_from_put_call['data']['type'], 'dois')
        self.assertEqual(json_from_put_call['data']['attributes']['event'], 'publish')

    @patch('datacite_doi_helper_object.DataCiteApi.add_new_doi')
    def test_create_dataset_draft_doi_fail(self, mock_add_new_doi):
        def resp1():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_add_new_doi.side_effect = [resp1()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.create_dataset_draft_doi, self.dataset, "Dataset Title String")
        mock_add_new_doi.assert_called()

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.update_doi_event_publish')
    def test_move_doi_state_from_draft_to_findable_happy_path(self, mock_update_doi_event_publish, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_update_doi_event_publish.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_put_entities.side_effect = [resp2()]

        doi_data = self.datacite_doi_helper.move_doi_state_from_draft_to_findable(self.dataset, "User Token String")

        mock_update_doi_event_publish.assert_called()
        mock_put_entities.assert_called()
        self.assertEqual(doi_data, self.response_doi)

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.update_doi_event_publish')
    def test_move_doi_state_from_draft_to_findable_fail1(self, mock_update_doi_event_publish, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_update_doi_event_publish.side_effect = [resp1()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.move_doi_state_from_draft_to_findable, self.dataset, "Dataset Title String")
        mock_update_doi_event_publish.assert_called()
        mock_put_entities.assert_not_called()

    @patch('datacite_doi_helper_object.EntityApi.put_entities')
    @patch('datacite_doi_helper_object.DataCiteApi.update_doi_event_publish')
    def test_move_doi_state_from_draft_to_findable_fail2(self, mock_update_doi_event_publish, mock_put_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.response_doi
            return r
        mock_update_doi_event_publish.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 400
            r.json = lambda: self.response_doi
            return r
        mock_put_entities.side_effect = [resp2()]

        self.assertRaises(requests.RequestException, self.datacite_doi_helper.move_doi_state_from_draft_to_findable, self.dataset, "Dataset Title String")
        mock_update_doi_event_publish.assert_called()
        mock_put_entities.assert_called()
