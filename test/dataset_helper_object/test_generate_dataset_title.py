import unittest
from unittest.mock import patch

import requests
from dataset_helper_object import DatasetHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestGenerateDatasetTitle(unittest.TestCase):

    @patch("dataset_helper_object.load_flask_instance_config")
    def setUp(self, mock_load_flask_instance_config):
        mock_load_flask_instance_config.return_value = {'ENTITY_WEBSERVICE_URL': 'eUrl', 'SEARCH_WEBSERVICE_URL': 'sUrl'}
        self.dataset_helper = DatasetHelper()

        # For a "Dataset": response.json() from requests.get(url = f"{_entity_api_url}/entities/{dataset_uuid}", ...)
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.dataset = {'uuid': self.dataset_uuid, 'data_types': ['bulk-RNA', 'IMC']}
        self.user_token = "fake token"

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntityApi.get_ancestors')
    @patch('dataset_helper_object.SearchApi.get_assaytype')
    def test_generate_dataset_title_happy_path(self, mock_get_assaytype, mock_get_ancestors, mock_url_open):
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
                               'organ': 'AO'  # description: Aorta
                              },
                              {'entity_type': 'Donor',
                               'metadata': {
                                   'organ_donor_data': [{'grouping_concept_preferred_term': 'Age', 'data_value': '99'},
                                                        {'grouping_concept_preferred_term': 'Race', 'preferred_term': 'Martian'},
                                                        {'grouping_concept_preferred_term': 'Sex', 'preferred_term': 'M'}
                                                        ]
                                            }
                               }]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp4()]

        result = self.dataset_helper.generate_dataset_title( self.dataset, self.user_token)

        self.assertTrue(type(result) is str)
        #  f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"
        self.assertEqual(result, 'Imaging Mass Cytometry and Bulk RNA-seq data from the aorta of a 99-year-old martian m')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntityApi.get_ancestors')
    @patch('dataset_helper_object.SearchApi.get_assaytype')
    def test_generate_dataset_title_no_grouping_concept_preferred_terms(self, mock_get_assaytype, mock_get_ancestors, mock_url_open):
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
                               'organ': 'AO'  # description: Aorta
                              }]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp4()]

        result = self.dataset_helper.generate_dataset_title(self.dataset, self.user_token)

        self.assertTrue(type(result) is str)
        #  f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"
        self.assertEqual(result, 'Imaging Mass Cytometry and Bulk RNA-seq data from the aorta of a <age>-year-old <race> <sex>')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_url_open.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntityApi.get_ancestors')
    @patch('dataset_helper_object.SearchApi.get_assaytype')
    def test_generate_dataset_title_no_organ(self, mock_get_assaytype, mock_get_ancestors, mock_url_open):
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
                               'specimen_type': 'Organ'
                              },
                              {'entity_type': 'Donor',
                               'metadata': {
                                   'organ_donor_data': [{'grouping_concept_preferred_term': 'Age', 'data_value': '99'},
                                                        {'grouping_concept_preferred_term': 'Race', 'preferred_term': 'Martian'},
                                                        {'grouping_concept_preferred_term': 'Sex', 'preferred_term': 'M'}
                                                        ]
                                            }
                               }]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp4()]

        result = self.dataset_helper.generate_dataset_title( self.dataset, self.user_token)

        self.assertTrue(type(result) is str)
        #  f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"
        self.assertEqual(result, 'Imaging Mass Cytometry and Bulk RNA-seq data from the <organ_desc> of a 99-year-old martian m')
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        # because no 'organ:' is called by mock_get_ancestors
        mock_url_open.assert_not_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntityApi.get_ancestors')
    @patch('dataset_helper_object.SearchApi.get_assaytype')
    def test_generate_dataset_title_no_organ_description(self, mock_get_assaytype, mock_get_ancestors, mock_url_open):
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
                               'organ': 'BL'  # description is missing from mock_url_open response
                              },
                              {'entity_type': 'Donor',
                               'metadata': {
                                   'organ_donor_data': [{'grouping_concept_preferred_term': 'Age', 'data_value': '99'},
                                                        {'grouping_concept_preferred_term': 'Race', 'preferred_term': 'Martian'},
                                                        {'grouping_concept_preferred_term': 'Sex', 'preferred_term': 'M'}
                                                        ]
                                            }
                               }]
            return r
        mock_get_ancestors.side_effect = [resp3()]

        def resp4():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp4()]

        self.assertRaises(TypeError, self.dataset_helper.generate_dataset_title,  self.dataset, self.user_token)
        mock_get_assaytype.assert_called()
        mock_get_ancestors.assert_called()
        mock_url_open.assert_called()
