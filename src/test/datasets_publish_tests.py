#!/usr/bin/env python

import argparse
import os
import sys
import requests
import json

from hubmap_commons import neo4j_driver
from ingest_file_helper import IngestFileHelper


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def vprint(*pargs, **pkwargs) -> None:
    if 'VERBOSE' in os.environ and os.environ['VERBOSE'] == 'True':
        print(*pargs, file=sys.stderr, **pkwargs)


def parse_cfg(cfg_file) -> dict:
    conf = {}
    with open(cfg_file) as fp:
        for line in fp:
            line = line.strip()
            if line.startswith('#') or len(line) == 0:
                continue
            line = line.rstrip('\n')
            key, val = line.strip().split('=', 1)
            key = key.strip()
            conf[key] = val.strip().strip("'\"")
    return conf


def query_str(data_access_level: str) -> str:
    return "MATCH (dn:Donor)-[*]->(s:Sample)-[:ACTIVITY_INPUT]->(:Activity)-[:ACTIVITY_OUTPUT]->" \
            f"(ds:Dataset {{status:'QA', data_access_level: '{data_access_level}'}}) " \
            "WHERE not ds.ingest_metadata is null AND not ds.contacts is null AND " \
            "not ds.contributors is null AND not dn.metadata is null " \
            "RETURN ds.uuid as ds_uuid, ds.group_name as ds_group_name;"


def mkdir_p(path: str) -> None:
    os.system(f"mkdir -p {path}")


def rm_f(path: str) -> None:
    if os.path.exists(path):
        os.remove(path)


def rm_rf(path: str) -> None:
    if os.path.exists(path):
        os.system(f"rm -rf {path}")


def publish_and_check(dataset_uuid: str, metadata_json_path: str) -> None:
    route_url: str = f'{args.ingest_url}/datasets/{dataset_uuid}/publish'
    vprint(f'route url: {route_url}')
    headers: dict = {
        'Authorization': f'Bearer {args.bearer_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    response = requests.put(route_url, headers=headers)
    if response.status_code != 200:
        eprint(f"Unexpected status code {response.status_code} from url {route_url}; response text: {response.text}")
        exit()
    if not args.skip_file_work:
        if not os.path.exists(metadata_json_path):
            eprint(f"metadata.json file not found where expected {metadata_json_path}")
            exit()
        with open(metadata_json_path) as json_fp:
            d: dict = json.load(json_fp)
            json_fp.close()
            if not d.get('samples') or not d.get('organs') or not d.get('donors'):
                eprint(f"Missing one of the required fields 'samples', or 'organs', or 'donors'")
            if d.get('status') != "Published":
                eprint(f"Dataset should have 'Published' status")


class RawTextArgumentDefaultsHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawTextHelpFormatter
):
    pass


# https://docs.python.org/3/howto/argparse.html
parser = argparse.ArgumentParser(
    description='''
    "Script to test app.py:publish_datastage()

    http://18.205.215.12:7474/browser/ (see app.cfg for username and password)

    Then use this call replacing ds.uuid with the value of ds.uuid...
    curl -v --location --request PUT 'http://localhost:8484/datasets/ds.uuid/publish?suspend-indexing-and-acls=true' --header "Authorization: Bearer $TOKEN"

    Tests using both protected and consortium identifiers.
    
    Login through the UI to get the credentials...
    https://ingest.dev.hubmapconsortium.org/
    In Firefox (Tools > Browser Tools > Web Developer Tools). Click on "Storage" then the dropdown for "Local Storage"
    and then the url. Take the 'groups_token' as the 'bearer_token' below...
    
    LOCALLY RUN AND TEST:
    /Users/cpk36/Documents/Git/ingest-api/src/test/datasets_publish_tests.py ../instance/app.cfg http://127.0.0.1:8484 BEARER_TOKEN -v
    
    OS X NOTE: For this to work (951)subprocess.py:__init__() self._execute_child() must be commented out because it calls
    setfacl which does not exist on OS X
    
    ALSO: ingest_file_helper.py(194) set_dataset_permissions(..., trial_run = True): from False.
    
    REMOTELY RUN AND GET PATHS TO MANUALLY TEST:
    /Users/cpk36/Documents/Git/ingest-api/src/test/datasets_publish_tests.py ../instance/app_dev.cfg https://ingest-api.dev.hubmapconsortium.org BEARER_TOKEN -s -v
    ''',
    formatter_class=RawTextArgumentDefaultsHelpFormatter)
parser.add_argument('cfg_file',
                    help='Configuration file (instance/app.cfg) with required information such as base data directory'
                         '(used to calculate absolute path to dataset), any API service urls needed,'
                         'any Neo4j connection information needed, any passwords, tokens, etc...')
parser.add_argument('ingest_url',
                    help='url for ingest-api microservice (should be http://127.0.0.1:8484)')
parser.add_argument('bearer_token',
                    help='groups_token from Local Storage when logged into ingest-dev (see above)')
parser.add_argument("-s", "--skip_file_work", action="store_true",
                    help='use this if the ingest_url is other than localhost because then we cannot change the file system')
parser.add_argument("-v", "--verbose", action="store_true",
                    help='verbose output')

args = parser.parse_args()
os.environ['VERBOSE'] = str(args.verbose)

config = parse_cfg(args.cfg_file)


try:
    neo4j_driver_instance = neo4j_driver.instance(config['NEO4J_SERVER'],
                                                  config['NEO4J_USERNAME'],
                                                  config['NEO4J_PASSWORD'])

    vprint("Initialized neo4j_driver module successfully :)")
except Exception:
    eprint("Failed to initialize the neo4j_driver module")
    exit(1)

ingest_helper = IngestFileHelper(config)

consortium_path: str = config['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
protected_path: str = config['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
public_path: str = config['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']

#     Needs a dataset in 'Q/A' status and needs to be primary.
#
#     From the query 'ds.data_access_level' tells you whether you need to use the directory in
#     GLOBUS_PUBLIC_ENDPOINT_FILEPATH (public), GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH (consortium),
#     or GLOBUS_PROTECTED_ENDPOINT_FILEPATH (protected).
#     In that directory create the directories with the values of `ds.group_name/ds.uuid`.
#     In Globus Groups (https://app.globus.org/groups) you will also need to be associated with
#     the group for `ds.group_name`.
#     Use 'https://ingest.dev.hubmapconsortium.org/' to get the 'Local Storage/info/groups_token' for the $TOKEN
with neo4j_driver_instance.session() as neo4j_session:
    query_consortium: str = query_str('consortium')
    rval = neo4j_session.run(query_consortium).data()

    dataset_uuid: str = rval[0]['ds_uuid']
    dataset_group_name: str = rval[0].get('ds_group_name')

    full_consortium_path: str = f"'{consortium_path}/{dataset_group_name}/{dataset_uuid}'"
    vprint(f'Full consortium path: {full_consortium_path}')
    full_public_path: str = os.path.join(public_path, dataset_uuid)
    vprint(f'Full public path: {full_public_path}')
    metadata_json_path: str = os.path.join(full_public_path, 'metadata.json')
    vprint(f'Metadata json path: {metadata_json_path}')

    if not args.skip_file_work:
        vprint('File work!!!')
        mkdir_p(full_consortium_path)
        mkdir_p(public_path)
        os.system(f"touch {os.path.join(full_consortium_path, 'secondary_analysis.h5ad')}")
        copy_path: str = os.path.join(full_public_path, dataset_uuid)
        rm_f(copy_path)
        rm_f(metadata_json_path)

    publish_and_check(dataset_uuid, metadata_json_path)


with neo4j_driver_instance.session() as neo4j_session:
    query_protected: str = query_str('protected')
    rval = neo4j_session.run(query_protected).data()

    dataset_uuid: str = rval[0]['ds_uuid']
    dataset_group_name: str = rval[0].get('ds_group_name')

    full_protected_path: str = f"'{protected_path}/{dataset_group_name}/{dataset_uuid}'"
    vprint(f'Full protected path: {full_protected_path}')
    metadata_json_path: str = f"'{protected_path}/{dataset_group_name}/{dataset_uuid}/metadata.json'"
    vprint(f'Metadata json path: {metadata_json_path}')

    if not args.skip_file_work:
        vprint('File work!!!')
        mkdir_p(full_protected_path)
        os.system(f"touch '{protected_path}/{dataset_group_name}/{dataset_uuid}/secondary_analysis.h5ad'")
        rm_f(metadata_json_path)

    publish_and_check(dataset_uuid, metadata_json_path[1:-1])

neo4j_driver_instance.close()
print("Done!")
