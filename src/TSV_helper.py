import logging
from pathlib import Path
import csv
# @MAX Is this the right way to get this in here? with a _helper?  OR should this go in Utils? 
# OR an upcomming Contributors Helper? 
from hubmap_commons.hubmap_const import HubmapConst

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

class TSVError(Exception):
    def __init__(self, error):
        self.errors = f"{list(error.keys())[0]}: {list(error.values())[0]}"

def tsv_reader_wrapper(path, encoding: str) -> list:
    with open(path) as f:
        rows = list(csv.DictReader(f, dialect="excel-tab"))
        # row = list(csv.DictReader(f, dialect="excel-tab"))
        f.close()
    return rows
