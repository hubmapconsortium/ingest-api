import requests
import logging

from requests.auth import HTTPBasicAuth

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


# Configurations
DATACITE_CLIENT_ID = ''
DATACITE_CLIENT_PASSWORD = ''
DATACITE_API_URL = 'https://api.test.datacite.org/dois '
HUBMAP_PREFIX = '10.80478'

json_to_post = {
  "data": {
    "id": dataset['hubmap_id'],
    "type": "dois",
    "attributes": {
      "event": "publish",
      "doi": f"{HUBMAP_PREFIX}/{dataset['hubmap_id']}",
      "creators": dataset['creators'],
      "titles": [{
        "title": dataset['title']
      }],
      "publisher": "DataCite e.V.",
      "publicationYear": 2016,
      "types": {
        "resourceTypeGeneral": "Text"
      },
      "url": "https://schema.datacite.org/meta/kernel-4.0/index.html",
      "schemaVersion": "http://datacite.org/schema/kernel-4"
    }
  }
}

request_headers = {
    'Content-Type': 'application/vnd.api+json'
}

# Make the request using Basic Auth
# Disable ssl certificate verification
response = requests.post(url = DATACITE_API_URL, auth = HTTPBasicAuth(DATACITE_CLIENT_ID, DATACITE_CLIENT_PASSWORD), headers = request_headers, json = json_to_post, verify = False, params = query_parms) 

# Invoke .raise_for_status(), an HTTPError will be raised with certain status codes
response.raise_for_status()

if response.status_code == 200:
    logger.info("======registered DOI via DataCite======")
else:
    msg = f"Unable to register DOIs via DataCite" 
    
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

    logger.debug("======status code from DataCite======")
    logger.debug(response.status_code)

    logger.debug("======response text from DataCite======")
    logger.debug(response.text)

    # Also bubble up the error message from DataCite
    raise requests.exceptions.RequestException(response.text)