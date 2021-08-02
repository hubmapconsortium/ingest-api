import unittest

from unittest.mock import Mock, MagicMock, patch
from dataset_helper_object import DatasetHelper


class TestInit(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.logger.info = MagicMock(name='info', return_value=None)

    @patch('dataset_helper_object.DatasetHelper.__init__', return_value=None)
    def test_init(self, mock_dataset_helper_object_init):
        dataset_helper1 = DatasetHelper()
        self.assertIsInstance(dataset_helper1, object)
        dataset_helper2 = DatasetHelper()
        self.assertIsInstance(dataset_helper2, object)
        self.assertNotEqual(dataset_helper1, dataset_helper2)