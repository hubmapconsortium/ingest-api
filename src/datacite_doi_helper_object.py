import os
import sys
import time
import requests
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from flask import Flask
from api.datacite_api import DataCiteApi
from api.entity_api import EntityApi
from dataset_helper_object import DatasetHelper
import ast

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
                instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

    return app.config


class DataCiteDoiHelper:

    def __init__(self):
        config = load_flask_instance_config()

        # Login "Account ID" and "Password" for doi.test.datacite.org
        self.datacite_repository_id = config['DATACITE_REPOSITORY_ID']
        self.datacite_repository_password = config['DATACITE_REPOSITORY_PASSWORD']
        # Prefix, e.g., 10.80478 for test...
        self.datacite_hubmap_prefix = config['DATACITE_HUBMAP_PREFIX']
        # DataCite TEST API: https://api.test.datacite.org/
        self.datacite_api_url = config['DATACITE_API_URL']
        self.entity_api_url = config['ENTITY_WEBSERVICE_URL']

    def safely_convert_string(self, to_convert: object) -> list:
        # from entity-api this will be a json array, from Neo4j it will be a string...
        if not isinstance(to_convert, str):
            return to_convert
        try:
            return ast.literal_eval(to_convert)
        except (SyntaxError, ValueError, TypeError) as e:
            msg = f"Failed to convert the source string with ast.literal_eval(); msg: {repr(e)}"
            logger.exception(msg)
            raise ValueError(msg)

    # See: https://support.datacite.org/docs/schema-40#table-3-expanded-datacite-mandatory-properties
    def build_common_dataset_contributor(self, dataset_contributor: dict) -> dict:
        contributor = {}

        # This automatically sets the name based on familyName, givenname without using the 'name' value stored in Neo4j
        # E.g., "Smith, Joe"
        contributor['nameType'] = 'Personal'

        if 'first_name' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#72-givenname
            contributor['givenName'] = dataset_contributor['first_name']

        if 'last_name' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#73-familyname
            contributor['familyName'] = dataset_contributor['last_name']

        if 'affiliation' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#75-affiliation
            contributor['affiliation'] = [
                {
                    'name': dataset_contributor['affiliation']
                }
            ]

        # NOTE: ORCID provides a persistent digital identifier (an ORCID iD) that you own and control, and that distinguishes you from every other researcher.
        if 'orcid_id' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#74-nameidentifier
            contributor['nameIdentifiers'] = [
                {
                    'nameIdentifierScheme': 'ORCID',
                    'nameIdentifier': dataset_contributor['orcid_id'],
                    'schemeUri': 'https://orcid.org/' 
                }
            ]

        return contributor

    # See: https://support.datacite.org/docs/schema-optional-properties-v43#7-contributor
    def build_doi_contributors(self, dataset: dict) -> list:
        dataset_contributors = self.safely_convert_string(dataset['contacts'])
        contributors = []

        for dataset_contributor in dataset_contributors:
            contributor = self.build_common_dataset_contributor(dataset_contributor)
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#7a-contributortype
            contributor['contributorType'] = 'ContactPerson'

            if len(contributor) != 0:
                contributors.append(contributor)
    
        if len(contributors) == 0:
            return None

        return contributors

    def build_doi_creators(self, dataset: object) -> list:
        dataset_creators = self.safely_convert_string(dataset['contributors'])
        creators = []

        for dataset_creator in dataset_creators:
            creator = self.build_common_dataset_contributor(dataset_creator)

            if len(creator) != 0:
                creators.append(creator)

        if len(creators) == 0:
            return None

        return creators


    """
    Register a draft DOI with DataCite

    Draft DOIs may be updated to either Registered or Findable DOIs. 
    Registered and Findable DOIs may not be returned to the Draft state, 
    which means that changing the state of a Draft DOI is final. 
    Draft DOIs remain until the DOI owner either deletes them or converts them to another state.

    Parameters
    ----------
    dataset: dict
        The dataset dict to be published

    Returns
    -------
    dict
        The registered DOI details
    """
    def create_dataset_draft_doi(self, dataset: dict) -> object:
        if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
            datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password,
                                       self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
            
            # Get publication_year, default to the current year
            publication_year = int(datetime.now().year)
            if 'published_timestamp' in dataset:
                # The timestamp stored with using neo4j's TIMESTAMP() function contains milliseconds
                publication_year = int(datetime.fromtimestamp(dataset['published_timestamp']/1000).year)

            response = datacite_api.create_new_draft_doi(dataset['hubmap_id'], 
                                                dataset['uuid'],
                                                self.build_doi_contributors(dataset), 
                                                dataset['title'],
                                                publication_year,
                                                self.build_doi_creators(dataset))

            if response.status_code == 201:
                logger.info(f"======Created draft DOI for dataset {dataset['uuid']} via DataCite======")
                doi_data = response.json()
                logger.debug("======resulting json from DataCite======")
                logger.debug(doi_data)
                return doi_data
            else:
                # Log the full stack trace, prepend a line with our message
                logger.exception(f"Unable to create draft DOI for dataset {dataset['uuid']} via DataCite")
                logger.debug(f'======Status code from DataCite {response.status_code} ======')
                logger.debug("======response text from DataCite======")
                logger.debug(response.text)

                # Also bubble up the error message from DataCite
                raise requests.exceptions.RequestException(response.text)
        else:
            raise KeyError('Either the entity_type of the given Dataset is missing or the entity is not a Dataset')

    """
    Move the DOI state from draft to findable, meaning publish this dataset 
    
    Parameters
    ----------
    dataset: dict
        The dataset dict to be published
    user_token: str
        The user's globus nexus token
    
    Returns
    -------
    dict
        The published datset entity dict with updated DOI properties
    """
    def move_doi_state_from_draft_to_findable(self, dataset: dict, user_token: str) -> object:
        if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
            datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password,
                                       self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
            response = datacite_api.update_doi_event_publish(dataset['hubmap_id'])

            if response.status_code == 200:
                logger.info(f"======Published DOI for dataset {dataset['uuid']} via DataCite======")
                doi_data = response.json()
                logger.debug("======resulting json from DataCite======")
                logger.debug(doi_data)

                # Then update the dataset DOI properties via entity-api after the DOI gets published
                try:
                    doi_url = doi_data['data']['attributes']['url']
                    doi_name = datacite_api.build_doi_name(dataset['hubmap_id'])
                    entity_api = EntityApi(user_token, self.entity_api_url)
                    updated_dataset = self.update_dataset_after_doi_published(dataset['uuid'], doi_name, doi_url, entity_api)

                    return updated_dataset
                except requests.exceptions.RequestException as e:
                    raise requests.exceptions.RequestException(e)
            else:
                # Log the full stack trace, prepend a line with our message
                logger.exception(f"Unable to publish DOI for dataset {dataset['uuid']} via DataCite")
                logger.debug(f'======Status code from DataCite {response.status_code} ======')
                logger.debug("======response text from DataCite======")
                logger.debug(response.text)

                # Also bubble up the error message from DataCite
                raise requests.exceptions.RequestException(response.text)
        else:
            raise KeyError('Either the entity_type of the given Dataset is missing or the entity is not a Dataset')

    """
    Update the dataset's properties after DOI is published (Draft -> Findable) 
    
    Parameters
    ----------
    dataset_uuid: str
        The dataset uuid
    doi_name: str
        The registered doi: prefix/suffix
    doi_url: str
        The registered doi_url
    entity_api
        The EntityApi object instance
    
    Returns
    -------
    dict
        The entity dict with updated DOI properties
    """
    def update_dataset_after_doi_published(self, dataset_uuid: str, doi_name: str, doi_url: str, entity_api: EntityApi) -> object:

        # Update the registered_doi, and doi_url properties after DOI made findable
        # Changing Dataset.status to "Published" and setting the published_* properties
        # are handled by another script
        # See https://github.com/hubmapconsortium/ingest-ui/issues/354
        dataset_properties_to_update = {
            'registered_doi': doi_name,
            'doi_url': doi_url
        }
        response = entity_api.put_entities(dataset_uuid, dataset_properties_to_update)

        if response.status_code == 200:
            logger.info("======The dataset {dataset['uuid']}  has been updated with DOI info======")
            updated_entity = response.json()
            logger.debug("======updated_entity======")
            logger.debug(updated_entity)

            return updated_entity
        else:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to update the DOI properties of dataset {dataset_uuid}")
            logger.debug(f'======Status code from DataCite {response.status_code} ======')
            logger.debug("======response text from entity-api======")
            logger.debug(response.text)

            # Also bubble up the error message from entity-api
            raise requests.exceptions.RequestException(response.text)


# Running this python file as a script
# cd src; python3 -m datacite_doi_helper_object <user_token> <dataset_uuid>
if __name__ == "__main__":
    datasets_test = [
        '2dca1bf5832a4102ba780e9e54f6c350', 
        'c03acf2de0caff5e5850e0f76d555e1b'
    ]

    datasets_1 = [
        '2dca1bf5832a4102ba780e9e54f6c350', 
        'c03acf2de0caff5e5850e0f76d555e1b', 
        '399643b5aed6b71edee96d4bf9e0d306', 
        '8a238da50c0c0436510b857c21e4e792', 
        '8776e9183d5f85d90535a0b1b3b4e32a', 
        '3683b49e27133c064ccbd59ff9723e7c', 
        '4081680ef553db5f91fb3587dde595b6', 
        '7fd04d1aba61c35843dd2eb6a19d2545', 
        'b40eb3abccf2341f274cfd4ba809c03e', 
        '617aa0f0fc9a4ad38ecd96afad012575', 
        'a5234e06fed9a14ee8d29c5aa0258ba5', 
        '9a6403bb0423e62950926a7d4fdab45b', 
        '45c5111e579800c021fd5dfaedc614c2', 
        '6618f3be3571e757aa473d1a3e60b356', 
        '49cf1e5fa366852bd2b73f0d8ea206f5', 
        '989181f44061257701eca7c0b63e0f9f', 
        '2523d502e8bdd90d461aad4ac95a2172', 
        '1a4f3118a596ac20ab022913c83a772f', 
        '3f1657d4f4d883ae17e9fffe6723a5b5', 
        '6e5726513c1cc8b64933f5a629692ca8', 
        '256795b18af5b1d318e2326266053f7e', 
        '4554c7a5632d619b740cb39d3207acc0', 
        'c5b156bda4b396bfe8a06d981e155149', 
        '7ead905ab166404a0544c53ccc311f41', 
        'b7a2c05fdd9ddd0c83c9786ede98a24e', 
        '75edcda4f3ff5bef72383d5d082438c2', 
        'bdcaa8d710bfb837dc2982c1cc4f67c8', 
        'e21e76dbfcf94f3de679a284c8aa9bd1', 
        '03043e079260d180099579045f16cd53', 
        'd36df353338a4a450f2282c65218f16c', 
        '5c5ac37add144e8a9707d2cd7791e694', 
        '077f7862f6306055899374c7807a30c3', 
        '4852fecbbb3fe8fd8a4b897f26941dd9', 
        '4df8eb42549d6954d0b98b18cb92d9b6', 
        '0dc91e6484430c2db25b6765dd6aa565', 
        'a6ccc344f88a164766d1251053173009', 
        '4c0479bd703d8be3c2834dd1b6773b4c', 
        '2c3540e2b1040c06612698d80ecab56a', 
        'e0ba24d0c4dab528e46aab3f67a1aae8', 
        'e69fb303e035192a0ee38a34e4b25024', 
        'e3aa11ba0218456e2cc9302f6b1d9d1c', 
        '65f12a80f54438ea3bf5c7200ecd70a3', 
        '4514230f7473a496201a4e45c4ff9568', 
        '776bd778f20409d8ce2dd8f5bf5789ae', 
        '8dd0ef5cafa3541cf9f0661db64662b7', 
        'f0c58e670ceb445e6ab02c6a20c83aee', 
        '4a4c3947a7590031d1ff405557354fdb', 
        'aedc30c204870180673b6ece299f2eb1', 
        'c2778cdd0a18e6f1ca755cbf65511aed', 
        '4e1da648c2a1451edba33d991dc163ab', 
        '392ef2593e8cfcc9b1431a2614de3dbf', 
        '620e742ae8401461013804e8abf1a56a', 
        '4a69340c702774210d5452a6ae80f3c7', 
        'bca3d31804ecc8be096d0b7691419335', 
        'db0dc651c8b2a430a81b5c30d6fb6f7b', 
        '2cab54a6f67dcab243e86053f83b3690', 
        '34d3a6eeb06ddc1681c788113e66d52d', 
        '3ce5e603c9f6187b2c8f16340924355d', 
        '805f8a7aa537be9024685d065136e619', 
        '56cd9eb9f27564c34bfe4eb843d9b969', 
        'e7f28c44029ada6b1431354afeac61ff', 
        'ac1a2b21f3b25950bf340280a59b6ad4', 
        'dd353ca9ffc1ea3a6252c474363c7486', 
        '2b953ab8e97583a74944238af28b55cc', 
        '311837bf483627cc967e40092a251096', 
        '1b44f652bd13a713c9d1eb99b359a4fd', 
        '2c77b1cdf33dbed3dbfb74e4b578300e', 
        'f84c8edc36a65f248c2649ebbe52ad35', 
        '829949a05892c319595ed28887039134', 
        '6e9e4f61998006ee78c32af1596fa25a', 
        '2c2179ea741d3bbb47772172a316a2bf', 
        '69e5acda3ceefb02ef4363be64958c53', 
        'f1da42ceecf7aee4022a656c45566c18', 
        '26191c2719339be0c3fa6dc8a7ba3550', 
        '70a7c1ca60b687b780de65f155a14cce', 
        '9e05a10aada2453e65d31cb15d1fc8a0', 
        '1d266e247805145bc11d18723921d243', 
        '78c3b443b34f58b6814d7e42cf79ffb0', 
        'd66100e0c60a2006149a7ae25ceb9976', 
        'd973a70493040d827b48c0507e8583d9', 
        '24ae71286797caf4cafb34107ca59c69', 
        'b6ca91549e0e78caeb56201a88469efb', 
        'acf990fda01d0779884c62ce921a7494', 
        '021da50cc5ac86fa2f8e922c9057cff4', 
        '02bb10b41609c23409b77be427e4dc45', 
        '523965a112c67320c13745524daf49bf', 
        'a623ff25be3a93a7c0359b4d5e24a599', 
        '57f5dac52b0f95c95d231092678fe3f2', 
        '78995cc692cd03dbefc0c9bd54551c1b', 
        '688efaab879cf2a0566d1d1fe2ca663a', 
        '9b0f3151cf989d11800680eab120541a', 
        'b3f41a275f19a0ab14ecfedd6e36e8d4', 
        '189175f177efe332555ccae3f6268249', 
        '5192f045867ce517d4c2d98b4d6288ee', 
        '400557a6eaa81a53f225099d591044a7', 
        '93a7f14138e7da424eee938e1f0f00d8', 
        '8ce03670137bd0f4e11fc66295254ccd', 
        'dba94653e55bd0bee91458f5069e5854', 
        '5ce0c7057fc4368eb4e702533ca12d22', 
        '7f9f50e179d33f10461676e957b32d4f', 
        '5b6a0834ae89df3ddc5a09d28dcd2226', 
        'b449bd94ba1498ba8501d419eb985f51', 
        '86c5f68ae891b72357791a0de0a3308a', 
        '13fe014db62885655da9fa80535f6e64', 
        'b3cd200b6f7a9061e8b7bd6042d63bd3', 
        '6b0c3cc833e16488c5fe51ec2adbef17', 
        '484c62e89ff34fc41281c131ccc09ffb', 
        '462d21ffa95f8ac13b929b9ae97fa84c', 
        'b5fdfd5b7d1110ebfba9f2115e0bcaf8', 
        'b29f62452b8e333ffc62d2e69caa18fa', 
        'f92a933da30d4bb3a4f8d031f2bc5d3d', 
        'ea48629bd9ddbf461f2e746c6a0b9ce3', 
        '02a48d4d05c08260d905fef8139746d4', 
        '0d15ee98a8fd0aacac6f43197ca1fb15', 
        '02bd0196bab8c3978693d63539269700', 
        '802dd34d3d3a8437479668f0a1fd4477', 
        '74a2deca3ac29b45392d7e2e39c2024e', 
        'e957018ade5a1586060ee5bc3defa1b9', 
        'd7fa7f03af4d8ee669d57c57209393bb', 
        'd83c1b1f194bfd33a8f0110e1b9e8ab9', 
        'd9d4762c8639fe76553c81ce159b3e45', 
        '0186092a96f773bafb62721eb4399c6b', 
        '3acdb3ed962b2087fbe325514b098101', 
        '63495a0c6f833359218e7c7f991746ab', 
        '517539cee7b8ea5909150998f5486a17', 
        '71256e28c1393f391385a21ab14f78f6', 
        'd859a8c563558b7db0b73c6170ad84fd', 
        '0b10c4d5df6cb25fa12a67f7e72580ab', 
        'd926c41ac08f3c2ba5e61eec83e90b0c', 
        '8f0becaf2d0eea9df67e45b8d66d69ac', 
        'c6a254b2dc2ed46b002500ade163a7cc', 
        'eaad5ed4b3aa2186bd87e05ff28b593e', 
        '9046d09943f6a10b70544822de1d5752', 
        '149eea2020a082ea9dd5683bdaca67c9', 
        'df4571465db80f45c10bc29cf5342cde', 
        'c9799ce59c4518bd243555c92c4edc21', 
        '56fd9c83a140673c1b259612a91f2bb0', 
        'bf447e198a99cb780d93437f05b2452d', 
        '63c9ad59d1db51551989d7dabd36dea9', 
        '3b9e41fa2326a845871cd20b35efb0c0', 
        'dcb845c82041eeb07020dec84e03ea97', 
        '4e54c868cca02be3a0538b03c1909c3d', 
        'be7059191ba49651655db7d333610ad2', 
        '4125c67860a0f659ffbbf101b278c62a', 
        '534418043eb8b1e8e6690123688bed09', 
        '0958dabdd6ea147193514524f8dc7cdd', 
        '16e9ba451dcad479781b272fb8a6ea05',
    ]


    datasets_2 = [
        'bae81c76d9baf591fc7455f570e3c41d', 
        '28481bdc81b2fac9c645ec95fc0e1824', 
        '3802f8843c090764d056b2e326a494ca', 
        '3d2d23e79d05583bd3b1a7f009b203ef', 
        'a99a132d06f46dc563cb47006b874ab1', 
        '6e501b057f0d19451012c03aa5442af2', 
        '724256834b9b5c19073559d422e59667', 
        'b4dc29f1b0bdc10ce57734655feb4428', 
        '4d3eb2a87cda705bde38495bb564c8dc', 
        'd7204812ade29562397bb60c99216794', 
        'f5e37d024e028f1beae9d384630b8107', 
        '2192b4d95d164631d8c984dcde3ea635', 
        '585c27740dd6f680c0dcaba323562939', 
        '03e1ae44e4c4a92ded0c1960336b83af', 
        '14e791d78e93de385869c09b101e9ce3', 
        'b713efaada56322c7f53aba18ddb904e', 
        'ba76a0aee94e03e866287d77866ead58', 
        '3cd30e8d3cfac233dc86be47c3508fdc', 
        'af8c7a2263bf77785bf75788143eef4e', 
        '30af16460b3f499e5bc803b794b61df0', 
        '0e9c6c75a7cdb5c2d4fdd242b4b0637f', 
        'd5e4547a1e72812284f7762e94a0f754', 
        'fe404f09cf1786cfd9ec45a3af62dc6f', 
        '6aa7ff3bf38a6b1a242b6d7d3198f44a', 
        'cad274bf30cdf90e246dfe56afcdf2c2', 
        '1e4f36238979459b6cb35f3a36bb299d', 
        'd31aa4d63ee3f71965fc7bccb3ef3d02', 
        'fa3f5482e3502d7d5d86c61157ee6a7a', 
        'c7038c10b1766e639ce263d5a177e5fd', 
        '055730a8c5486ec9bf66af90102e5626', 
        '52fab90faa97ba44dfde29e1fe740f48', 
        '048723fd5863d45d8a8e867f21e8af9f', 
        '68751a1150c6b24cec78c031390487bc', 
        '04e5fe708a31a40726cb204908cd5479', 
        '9d5f581f5a1081fda3c748402b13b09b', 
        'fc5807ae31c05679bc1048c79aaf92c5', 
        'e562cbe920567069d39b38b8f672bf5d', 
        'dac492687743a1c374ebb4fdc9a0a55a', 
        '81326ba2085657141f9932f135154e39', 
        '225280788b0c66d095d05c4e36a89b81', 
        '2a305a30f98deb4a3a6717f24edcbef9', 
        '0e71beaf2b67bae4c609df811a34d7ca', 
        '75ccc2ff3ce28137d2f5f6f34873747d', 
        '059d18392b5a8805337a0c8ef5d19b46', 
        'fa18feb84ec1c2fd66286ac47da24b9c', 
        '434243c3ccff2face69c37fe86d53b4f', 
        '42221548e4c709628522b64d48ba0a75', 
        '46f707a38043ac6d2cd6a3700979c8f8', 
        '1e002a7b641312095138750498a541de', 
        '973b5f2ce28a818e31d6148147feb6fc', 
        '812eb84d7f482e1c855f6cc37f554874', 
        '64b61aac0df17ddb916b88d2faa2ce7d', 
        '50c0c77c036397f98ad4c058fc9cd35a', 
        '16cf9755338257986a867a86d63c2b9b', 
        '16782d78da92510a67880e719af368f7', 
        '42f8aaeab5888c1789d630ca085d6688', 
        '227f4450f80d5c058f2f223adc806fb0', 
        'e81e134b69e297f7442c6e4050ffb464', 
        '9d607bbd57fd250c7444158f4f55598f', 
        '53f81503913a841f57f07835ce94a5b9', 
        '12ec5b881a24bd3da166fd64e52fcb93', 
        '74c08831f6c89b35d6df46bf88c3fbf0', 
        '07975e1e99bcd25fef9e6c72c46a8922', 
        'b57f7458986473e4fa57fd418ec9f894', 
        '058f837db913d4c3d0854eb2229c2695', 
        '13f68db2ce711221e402e6af2d8cad45', 
        '1e9b9d5ac57ac8bd4093f2503675a2cd', 
        '20fea3266c0b545def76080a3f545d0a', 
        '3d2c9295c0e05f4d81d23ee95e9dad23', 
        '45e9370bd4ee50c58d7a9cf34b4d2c70', 
        '46bab56124c61f7a66c50c3cde0aa596', 
        '47f4411d2eba0edaad6951c5cc1bc03b', 
        '484b359a4b9d4e370f52c4c3fef782a3', 
        '5eacc268fa94d3419580ff04c9a9c76d', 
        '64fb1a207109beb61404b7e0b4c60810', 
        '751d7b4638d6bfe51756669a4f192c00', 
        '7810dadcb43b35ef9de6378f3d53b532', 
        '7aed690c306ad4a8e08b7ec794e3a304', 
        '7e3f3b5d1890f9612efb91d3a820cdcc', 
        '7eef1634020f429f9855ff319ff0c65e', 
        '8030bee708b211203104616629480b52', 
        '8adc3c31ca84ec4b958ed20a7c4f4919', 
        '8d649002964c5c599b84ef38cac91410', 
        '9eb457ab0141f7ba734e337917a9bde9', 
        'ae7723aee8bc809afe0a05756bdf91de', 
        'd0be34d165e38dc3b9074aca578a1c46', 
        '91890e05edbd0a767092e10502b3ea99', 
        '6e7ba37ff1f480f2bfa8c5d29df2a3c1', 
        '6e95d91da2870ffc0a473c23038fc5e1', 
        'd4fae29feb0215a11b6e4d3072107e09', 
        'b6bbc59cb234d6b15deda7356567c3fb', 
        'cc856ea20548c887719abbac9a33a702', 
        '66175ea4190378474b7d73c49c470b9f', 
        '5753250650d5e5a4621e511594f93696', 
        '3ade70d66d10ed1d30fe005f672b2abf', 
        'd9e3c80a32567cde9b61e38ce8693559', 
        'f1fc56fe8e39a9c05328d905d1c4498e', 
        '3bb0a1651d75a53e69019812acd9d1a0', 
        '9d357d4bae9580895130bf0cd30fb99d', 
        '6aa9b45e2fe555a72335e21837334c52', 
        '60ed8e03152b51d5d9c8fc04e20fa5e3', 
        '146063814f6bd2b6546e950d0ca5f8c3', 
        '1d1a8376b558398588f92688314f23c5',  
    ]
    
    datasets = [
        '56b00177fa2bbd091a10dae8d57c9539', 
        '1e995c94f5e0affd76af014834a3c3a0',
        'b99153a1b16f28dd9ed12bc596795261', 
        '598e80e7888712571caed6488c191302', 
        '2ece1b8974483e14046fad953b35fedd', 
        '32b778c55269d2f7d4c650316cee7815', 
        'a1e1e169777c00084b3d46325561f374', 
        '6561d1c623a06c49ed5ecd68cb28cd15', 
        '8eccc1162147c6c240de384cffd1bcf4', 
        '54ef9a03bc7abbedc60a261bf49e1119', 
        'a11fe9d14122d4254acfefc9bf9faae4', 
        '9a519955a24cc30b7184177a5a89cecb', 
        'ac616d7b9149d279b29a5df3472486ac', 
        '0a6f5c1afbcc31622eb34daf88c2c016', 
        '1dd9a68210ef57c390f90b06851877a4', 
        '584620d30b86098ece9b96edb407c786', 
        '02e13b9b3cdc939cca397c42c2981dd1', 
        '109162ed40ede274202eab96bf640fa4', 
        '8122e6bbb32d0561eade1136d320a561', 
        '2f9e91ff774243ef11d148a2bf7a6822', 
        'dbf8d98f22c3579d1dd3dfb9931cf714', 
        '9ed95f2cf5c1b1a6af6250085d1aaf4a', 
        'bf6ec5a47c32f43b6d01ea58fa4723ca', 
        '8b347e7307c4e76f0ce20700ac77d38d', 
        '9ba91ddddfb2be8f06fd11230da0bbb3', 
        '46ed471a6b4ad5b97817ff2c26ef6ddd', 
        '2d6c51fbd0916109550a708d485903b7', 
        'dc289471333309925e46ceb9bafafaf4', 
        'ab27f3bda035e68b6df9edd84a860d9b', 
        '9d5698266ed4f019a7dbe5dae224a293', 
        '9c4fa632bd097331cd36cdee6af3882f', 
        '15ec310a304e1d4891cd33f4bc4cb197', 
        '489a9c1c01dcacb035ad1c71acf800d8', 
        'e075fde11ad2d20a7e164744001a40ab', 
        'e97f07695e7c14e25caea0ebf54870c7', 
        '48ca66f487e345342eda4972e0d639c6', 
        '2c00130ea77e93aaaf7362b566bc454e', 
        '36cfbc4e95abbfa9c43ccbc7d9951950', 
        'af8e5c3a7f66a105e8e19aba8a6fc6e3', 
        'b699132d500b27addfe1349729129121', 
        '1789590e753b67b472fd1cf786717d7f', 
        '96cf9f5d33a48e7e61e1ee00ad282b8a', 
        '9e9ccb2dd633440df0b8ec966f28edb6', 
        'a6a2fca893c7fd1b278ae8d018d28309', 
        '5b77e41cae48f02ba8bc358795a078b4', 
        '43326f3efb14c4f5f0a0b04bf1ab37d8'
    ]

    try:
        user_token = sys.argv[1]
        # try:
        #     dataset_uuid = sys.argv[2]
        # except IndexError as e:
        #     msg = "Missing dataset uuid argument"
        #     logger.exception(msg)
        #     sys.exit(msg)
    except IndexError as e:
        msg = "Missing user token argument"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)
        sys.exit(msg)

    # Make sure that 'app.cfg' is pointed to DEV everything!!!
    config = load_flask_instance_config()
    entity_api = EntityApi(user_token, config['ENTITY_WEBSERVICE_URL'])

    count = 1
    for dataset_uuid in datasets:
        logger.debug(f"Begin {count}: ========================= {dataset_uuid} =========================")

        response = entity_api.get_entities(dataset_uuid)
        if response.status_code == 200:
            dataset = response.json()

            logger.debug(dataset)

            dataset_helper = DatasetHelper()

            data_cite_doi_helper = DataCiteDoiHelper()
            try:
                logger.debug("Create Draft DOI")

                data_cite_doi_helper.create_dataset_draft_doi(dataset)
            except requests.exceptions.RequestException as e:
                pass

            try:
                logger.debug("Move Draft DOI -> Findable DOI")

                # To publish an existing draft DOI (change the state from draft to findable)
                data_cite_doi_helper.move_doi_state_from_draft_to_findable(dataset, user_token)
            except requests.exceptions.RequestException as e:
                logger.exception(e)
                sys.exit(e)
        else:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to query the target dataset with uuid: {dataset_uuid}")

            logger.debug("======status code from entity-api======")
            logger.debug(response.status_code)

            logger.debug("======response text from entity-api======")
            logger.debug(response.text)

        logger.debug(f"End {count}: ========================= {dataset_uuid} =========================")

        time.sleep(5)

        count = count + 1