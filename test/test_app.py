import unittest, json
from app import app
#from app_manager import verify_dataset_title_info

class BaseAppTests(unittest.TestCase) :

    def setUp(self):
        self.app = app.test_client()
        self.dataset_uuid = '12345678-1234-5678-1234-567812345678'
        self.token = 'token'
        self.headers = {'AUTHORIZATION': f'bearer   {self.token}'}

    def test_success(self):
        response = self.app.get(f'/datasets/{self.dataset_uuid}/verifytitleinfo', headers=self.headers)

        self.assertEqual(response.status_code, 200)

    def test_baduuld(self):
        response = self.app.get(f'/datasets/badUuid/verifytitleinfo', headers=self.headers)

        self.assertEqual(response.status_code, 400)
