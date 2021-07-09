import unittest

from unittest.mock import Mock, MagicMock
from dataset_helper_object import DatasetHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestDatasetHelper(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.logger.info = MagicMock(name='info', return_value=None)

        self.dataset_helper = DatasetHelper
        self.dataset_helper.__init__ = MagicMock(name='__init__', return_value=None)

        self.dataset_helper.get_assay_type_description = MagicMock(name='get_assay_type_description')
        self.dataset_helper.get_dataset_ancestors = MagicMock(name='get_dataset_ancestors')
        self.dataset_helper.get_organ_description = MagicMock(name='get_organ_description')
        self.dataset_helper.get_organ_description.return_value = 'Aorta'.lower()

        # For a "Dataset": response.json() from requests.get(url = f"{_entity_api_url}/entities/{dataset_uuid}", ...)
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.dataset = {'uuid': self.dataset_uuid, 'data_types': ['bulk-RNA', 'IMC']}
        # The assay_type description (below) is found in object associated with data_type (above) in....
        # search-api/src/search-schema/data/definitions/enums/assay_types.yaml
        self.dataset_helper.get_assay_type_description.return_value = 'Imaging Mass Cytometry and Bulk RNA-seq'

        self.user_token = "fake token"

    def test_generate_dataset_title_happy_path(self):
        # response.json() from requests..get(url=f"{_entity_api_url}/ancestors/{dataset_uuid}", ...)
        # for 'organ' values see: https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/organ_types.yaml
        self.dataset_helper.get_dataset_ancestors.return_value = [
            {'entity_type': 'Sample',
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
             }
        ]

        result = self.dataset_helper.generate_dataset_title(self.dataset_helper, self.dataset, self.user_token)

        self.assertTrue(type(result) is str)
        #  f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"
        self.assertEqual(result, 'Imaging Mass Cytometry and Bulk RNA-seq data from the aorta of a 99-year-old martian m')

    def test_generate_dataset_title_no_grouping_concept_preferred_terms(self):
        # response.json() from requests..get(url=f"{_entity_api_url}/ancestors/{dataset_uuid}", ...)
        self.dataset_helper.get_dataset_ancestors.return_value = [
            {'entity_type': 'Sample',
             'specimen_type': 'Organ',
             'organ': 'AO'  # description: Aorta
             }
        ]

        result = self.dataset_helper.generate_dataset_title(self.dataset_helper, self.dataset, self.user_token)

        self.assertTrue(type(result) is str)
        #  f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"
        self.assertEqual(result, 'Imaging Mass Cytometry and Bulk RNA-seq data from the aorta of a <age>-year-old <race> <sex>')
