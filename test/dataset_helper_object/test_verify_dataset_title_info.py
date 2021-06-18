import unittest
from array import array
from unittest.mock import Mock, MagicMock, PropertyMock

from api.entity_api import EntityApi
from api.search_api import SearchApi
from dataset_helper_object import DatasetHelper

from pprint import pprint


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestVerifyDatasetTitleInfo(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.logger.info = MagicMock(name='info', return_value=None)

        self.dataset_helper = DatasetHelper
        self.dataset_helper.__init__ = MagicMock(name='__init__', return_value=None)

        # For a "Dataset": response.json() from requests.get(url = f"{_entity_api_url}/entities/{dataset_uuid}", ...)
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.data_types = ['bulk-RNA', 'IMC']
        self.dataset = {'uuid': self.dataset_uuid, 'data_types': self.data_types}

        self.user_token = "fake token"

        self.search_api = SearchApi

        self.dataset_helper.get_organ_types_dict = MagicMock()
        self.dataset_helper.get_organ_types_dict.return_value = {
            'AO': {'description': 'Aorta'},
            'BL': {},
            'BD': {'description': 'Blood'},
            'BM': {'description': 'Bone Marrow'},
            'BR': {'description': 'Brain'}
        }

    def test_generate_dataset_title_entities_happy_path(self):
        entity_api = EntityApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        entity_api.get_assaytype = MagicMock()
        entity_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'BM'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
            }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 0)

    def test_generate_dataset_title_entities_not_found(self):
        entity_api = EntityApi
        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 404

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], f"Unable to get the target dataset with uuid: {self.dataset_uuid}")

    def test_generate_dataset_title_entities_description_not_found(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'BL'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
            }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Description for Organ code 'BL' not found in organ types file")

    def test_generate_dataset_title_entities_happy_path(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'xx'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
            }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Organ code 'xx' not found in organ types file")

    def test_generate_dataset_title_entities_no_organ(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
            }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'Organ key not found in organ types file')

    def test_generate_dataset_title_entities_no_specimine_type(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'organ': 'BM'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
                 }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid,
                                                               self.user_token)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'For entity_type==Sample, a specimen_type==organ not found')

    def test_generate_dataset_title_entities_no_race_no_sex(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 200

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'BM'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'}
                 ]
                 }}
        ]

        result = self.dataset_helper\
            .verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], f'Donor metadata.organ_donor_data grouping_concept_preferred_term race not found')
        self.assertEqual(result[1], f'Donor metadata.organ_donor_data grouping_concept_preferred_term sex not found')

    def test_generate_dataset_title_assaytype_not_found(self):
        entity_api = EntityApi
        search_api = SearchApi

        entity_api.get_entities = MagicMock()
        entity_api.get_entities.return_value.status_code = 200
        entity_api.get_entities.return_value.json = lambda: self.dataset
        search_api.get_assaytype = MagicMock()
        search_api.get_assaytype.return_value.status_code = 404

        entity_api.get_ancestors = MagicMock()
        entity_api.get_ancestors.return_value.status_code = 200
        entity_api.get_ancestors.return_value.json = lambda: [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'BM'},
            {'entity_type': 'Donor',
             'metadata':
                 {'organ_donor_data': [
                     {'grouping_concept_preferred_term': 'Age'},
                     {'grouping_concept_preferred_term': 'Race'},
                     {'grouping_concept_preferred_term': 'Sex'}
                 ]
            }}
        ]

        result = self.dataset_helper.verify_dataset_title_info(self.dataset_helper, self.dataset_uuid, self.user_token)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], 'Unable to query the assay type details of: bulk-RNA via search-api')
        self.assertEqual(result[1], 'Unable to query the assay type details of: IMC via search-api')