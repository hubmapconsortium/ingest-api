import unittest

from app import app


class BaseAppTests(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.token = 'token'
        self.headers = {'AUTHORIZATION': f'bearer   {self.token}'}

    def test_verify_dataset_title_info_success1(self):
        route = f'/datasets/{self.dataset_uuid}/verifytitleinfo'
        response = self.app.get(route, headers=self.headers)

        self.assertEqual(response.status_code, 200)

    def test_verify_dataset_title_info_success2(self):
        uuid = '12345678123456781234567812345678'
        route = f'/datasets/{uuid}/verifytitleinfo'
        response = self.app.get(route, headers=self.headers)

        self.assertEqual(response.status_code, 200)

    def test_verify_dataset_title_info_baduuld(self):
        route = f'/datasets/badUuid/verifytitleinfo'
        response = self.app.get(route, headers=self.headers)

        self.assertEqual(response.status_code, 400)
#        self.assertEqual(response.error, 'parameter uuid of dataset is required')
