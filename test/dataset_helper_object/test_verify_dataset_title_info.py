import unittest
from unittest.mock import patch

import hubmap_sdk
import requests
from dataset_helper_object import DatasetHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestVerifyDatasetTitleInfo(unittest.TestCase):

    @patch("dataset_helper_object.load_flask_instance_config")
    def setUp(self, mock_load_flask_instance_config):
        mock_load_flask_instance_config.return_value = {'ENTITY_WEBSERVICE_URL': 'eUrl', 'SEARCH_WEBSERVICE_URL': 'sUrl', 'UBKG_WEBSERVICE_URL': 'oURL'}
        self.dataset_helper = DatasetHelper()

        # For a "Dataset": response.json() from requests.get(url = f"{_entity_api_url}/entities/{dataset_uuid}", ...)
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.dataset_type = ['RNAseq', 'MIBI']
        self.dataset = {'uuid': self.dataset_uuid, 'dataset_type': self.dataset_type}
        self.user_token = "fake token"

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_happy_path(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                           'organ': 'BM'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                               {'organ_donor_data': [
                                                   {'grouping_concept_preferred_term': 'Age'},
                                                   {'grouping_concept_preferred_term': 'Race'},
                                                   {'grouping_concept_preferred_term': 'Sex'}
                                               ]
                                               }})

            entity = [dataset1, dataset2]
            return entity

        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            dataset = hubmap_sdk.Dataset(self.dataset)
            return dataset
        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": "Blood",
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r
        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 0)
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()

    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    def test_verify_dataset_title_info_entities_not_found(self, mock_get_entity_by_id):
        mock_get_entity_by_id.side_effect = [Exception]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], f"Unable to get the target dataset with uuid: {self.dataset_uuid}")
        mock_get_entity_by_id.assert_called()

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_organ_code_description_not_found(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                           'organ': 'BL'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                          {'organ_donor_data': [
                                            {'grouping_concept_preferred_term': 'Age'},
                                            {'grouping_concept_preferred_term': 'Race'},
                                            {'grouping_concept_preferred_term': 'Sex'}
                                          ]
                                           }})

            entity = [dataset1, dataset2]
            return entity

        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            dataset = hubmap_sdk.Dataset(self.dataset)
            return dataset
        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": null,
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r
        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 0)
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_organ_code_not_found_in_types_file(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                            'organ': 'xx'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                           {'organ_donor_data': [
                                           {'grouping_concept_preferred_term': 'Age'},
                                           {'grouping_concept_preferred_term': 'Race'},
                                           {'grouping_concept_preferred_term': 'Sex'}
                                             ]
                                           }})
            entity = [dataset1, dataset2]
            return entity
        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            dataset = hubmap_sdk.Dataset(self.dataset)
            return dataset
        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": "Blood",
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r
        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Organ code 'xx' not found in organ types file")
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()

    @patch('dataset_helper_object.urllib.request.urlopen')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_organ_key_not_found(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_open):
        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                               'specimen_type': 'Organ',
                               'sample_category': 'organ',})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                               'metadata':
                                 {'organ_donor_data': [
                                    {'grouping_concept_preferred_term': 'Age'},
                                    {'grouping_concept_preferred_term': 'Race'},
                                    {'grouping_concept_preferred_term': 'Sex'}
                                  ]
                               }})

            entity = [dataset1, dataset2]
            return entity
        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            dataset = hubmap_sdk.Dataset(self.dataset)
            return dataset
        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            r.read = lambda: b'AO:\r\n  description: Aorta\r\nBL:\r\n  \r\nBD:\r\n  description: Blood\r\nBM:\r\n  description: Bone Marrow\r\nBR:\r\n  description: Brain\r\n'
            # The 'when' needs the close method in the response....
            r.close = lambda: True
            return r
        mock_url_open.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'Organ key not found in sample_category organ')
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        # because no 'organ:' is called by mock_get_ancestors
        mock_url_open.assert_not_called()

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_no_race_no_sex(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                           'organ': 'BM'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                               {'organ_donor_data': [
                                                   {'grouping_concept_preferred_term': 'Age'}
                                               ]
                                               }})

            entity = [dataset1, dataset2]
            return entity

        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            dataset = hubmap_sdk.Dataset(self.dataset)
            return dataset
        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": "Blood",
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r
        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], f'Donor metadata.organ_donor_data grouping_concept_preferred_term race not found')
        self.assertEqual(result[1], f'Donor metadata.organ_donor_data grouping_concept_preferred_term sex not found')
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_assaytype_not_found(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        # https://github.com/hubmapconsortium/search-api/blob/main/src/search-schema/data/definitions/enums/assay_types.yaml

        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                           'organ': 'BM'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                               {'organ_donor_data': [
                                                   {'grouping_concept_preferred_term': 'Age'},
                                                   {'grouping_concept_preferred_term': 'Race'},
                                                   {'grouping_concept_preferred_term': 'Sex'}
                                               ]
                                               }})

            entity = [dataset1, dataset2]
            return entity

        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            entity = hubmap_sdk.Dataset(self.dataset)
            return entity

        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": "Blood",
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r

        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()

    @patch('dataset_helper_object.requests.get')
    @patch('dataset_helper_object.EntitySdk.get_entity_by_id')
    @patch('dataset_helper_object.EntitySdk.get_ancestors')
    def test_verify_dataset_title_info_dataset_data_types_missing(self, mock_get_ancestors, mock_get_entity_by_id, mock_url_get):
        # https://github.com/hubmapconsortium/search-api/blob/main/src/search-schema/data/definitions/enums/assay_types.yaml
        def resp1():
            dataset1 = hubmap_sdk.Dataset({'entity_type': 'Sample',
                                           'specimen_type': 'Organ',
                                           'sample_category': 'organ',
                                           'organ': 'BM'})
            dataset2 = hubmap_sdk.Dataset({'entity_type': 'Donor',
                                           'metadata':
                                             {'organ_donor_data': [
                                                {'grouping_concept_preferred_term': 'Age'},
                                                {'grouping_concept_preferred_term': 'Race'},
                                                {'grouping_concept_preferred_term': 'Sex'}
                                              ]
                                             }
                                           }
                                          )

            entity = [dataset1, dataset2]
            return entity
        mock_get_ancestors.side_effect = [resp1()]

        def resp2():
            entity = hubmap_sdk.Dataset({'uuid': self.dataset_uuid})
            return entity

        mock_get_entity_by_id.side_effect = [resp2()]

        def resp3():
            r = requests.Response()
            json_data = '''
            {
                "AO": "Aorta",
                "BD": "Blood",
                "BL": "Bladder",
                "BM": "Bone Marrow"
            }
            '''
            r._content = json_data.encode('utf-8')
            return r

        mock_url_get.side_effect = [resp3()]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'The dataset did not contain a ''dataset_type'' key')
        # Because dataset did not contain a ''dataset_type'' key...
        mock_get_ancestors.assert_called()
        mock_get_entity_by_id.assert_called()
        mock_url_get.assert_called()