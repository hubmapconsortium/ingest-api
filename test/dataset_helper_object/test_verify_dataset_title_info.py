import unittest
from unittest.mock import patch

import requests
from dataset_helper_object import DatasetHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestVerifyDatasetTitleInfo(unittest.TestCase):

    @patch("dataset_helper_object.load_flask_instance_config")
    def setUp(self, mock_load_flask_instance_config):
        mock_load_flask_instance_config.return_value = {'ENTITY_WEBSERVICE_URL': 'eUrl', 'SEARCH_WEBSERVICE_URL': 'sUrl'}
        self.dataset_helper = DatasetHelper()

        # For a "Dataset": response.json() from requests.get(url = f"{_entity_api_url}/entities/{dataset_uuid}", ...)
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.data_types = ['bulk-RNA', 'IMC']
        self.dataset = {'uuid': self.dataset_uuid, 'data_types': self.data_types}
        self.user_token = "fake token"

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_happy_path(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'BM'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 0)
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    def test_verify_dataset_title_info_entities_not_found(self, mock_get_entities):
        def resp4():
            r = requests.Response()
            r.status_code = 404
            r.json = lambda: None
            return r
        mock_get_entities.side_effect = [resp4()]

        result = self.dataset_helper.verify_dataset_title_info( self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], f"Unable to get the target dataset with uuid: {self.dataset_uuid}")
        mock_get_entities.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_organ_code_description_not_found(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'BL'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Description for Organ code 'BL' not found in organ types file")
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_organ_code_not_found_in_types_file(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'xx'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Organ code 'xx' not found in organ types file")
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_organ_key_not_found(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'Organ key not found in specimen_type organ')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        # because no 'organ:' is called by mock_get_ancestors
        mock_url_open.assert_not_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_no_race_no_sex(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'BM'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], f'Donor metadata.organ_donor_data grouping_concept_preferred_term race not found')
        self.assertEqual(result[1], f'Donor metadata.organ_donor_data grouping_concept_preferred_term sex not found')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_assaytype_not_found(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 404
            r.json = lambda: None
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 404
            r.json = lambda: None
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'BM'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: self.dataset
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], 'Unable to query the assay type details of: bulk-RNA via search-api')
        self.assertEqual(result[1], 'Unable to query the assay type details of: IMC via search-api')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    @patch('dataset_helper_object.SearchSdk.assayname')
    def test_verify_dataset_title_info_dataset_data_types_missing(self, mock_get_assaytype, mock_get_ancestors, mock_get_entities, mock_url_open):
        # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Imaging Mass Cytometry', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'description': 'Bulk RNA-seq', 'alt-names': [], 'primary': 'true', 'vitessce-hints': []}
            return r
        mock_get_assaytype.side_effect = [resp1(), resp2()]

        def resp3():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: [{'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'organ': 'BM'},
                              {'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }}]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'uuid': self.dataset_uuid}
            return r
        mock_get_entities.side_effect = [resp4()]

        def resp5():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp5()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'The dataset did not contain a ''data_types'' key')
        # Because dataset did not contain a ''data_types'' key...
        mock_get_assaytype.assert_not_called()
        mock_get_ancestors.assert_called()
        mock_get_entities.assert_called()
        mock_url_open.assert_called()
