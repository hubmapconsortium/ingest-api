#!/usr/bin/env python

import argparse
import os
import sys
import requests
import json
from urllib.parse import urlparse

from hubmap_commons import neo4j_driver
from hubmap_commons.hubmap_const import HubmapConst
from ingest_file_helper import IngestFileHelper

local_execution: bool = False


def eprint(*eargs, **kwargs) -> None:
    print(*eargs, file=sys.stderr, **kwargs)


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
            f"(ds:Dataset {{status:'QA', data_access_level:'{data_access_level}'}}) " \
            "WHERE not ds.ingest_metadata is null AND not ds.contacts is null AND " \
            "not ds.contributors is null AND not dn.metadata is null " \
            "RETURN ds.uuid as ds_uuid, ds.group_name as ds_group_name;"


def query_derived_str() -> str:
    """
    Bill Mar 18, 2024 3:45pm
    Because of the new addition of “multi-assay component” datasets and existing Publications you may run across
    just a few stragglers returned there that aren’t valid for publication at all, so I would use this (just adding
    a constraint on the Activity.creation_action)-- this would ONLY be used separately to find datasets.
    """
    return "MATCH (:Dataset)-[:ACTIVITY_INPUT]->(Activity {creation_action:'Central Process'})-[:ACTIVITY_OUTPUT]->(ds:Dataset {status:'QA'}) " \
           "RETURN ds.uuid as ds_uuid, ds.group_name as ds_group_name, " \
           "ds.data_access_level as ds_data_access_level;"


def mkdir_p(path: str) -> None:
    cmd: str = f"mkdir -p {path}"
    vprint(f"mkdir_p: {cmd}")
    os.system(cmd)


def rm_f(path: str) -> None:
    if os.path.exists(path):
        vprint(f"rm_f: {path}")
        os.remove(path)


def rm_rf(path: str) -> None:
    if os.path.exists(path):
        cmd: str = f"rm -rf {path}"
        vprint(f"rm_rf: {cmd}")
        os.system(cmd)


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
        eprint(f"Status code {response.status_code} from url {route_url}; response text: {response.text}")
    if local_execution:
        if not os.path.exists(metadata_json_path):
            eprint(f"metadata.json file not found {metadata_json_path}")
            return
        with open(metadata_json_path) as json_fp:
            d: dict = json.load(json_fp)
            json_fp.close()
            if not d.get('samples') or not d.get('organs') or not d.get('donors'):
                eprint(f"Missing one of the required fields 'samples', or 'organs', or 'donors'")
            if d.get('status') != "Published":
                eprint(f"Dataset should have 'Published' status")
    else:
        print(f"ls -al '{metadata_json_path}'")
        input("Please execute the above commands on the PSC server, and then press Enter to continue...")


class RawTextArgumentDefaultsHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawTextHelpFormatter
):
    pass


# https://docs.python.org/3/howto/argparse.html
parser = argparse.ArgumentParser(
    description='''
    "Script to test app.py:publish_datastage()
    
    There should be three tests (but there are only the first two implemented) where:
    1) Primary human genetic sequences = False (consortia) generate a metadata.json,
    2) Primary human genetic sequences = True (protected) generate a metadata.json,
    3) Primary a derived/processed dataset (datasets that hang off other datasets) DO NOT generate a metadata.json.

    http://18.205.215.12:7474/browser/ (see app.cfg for username and password)

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
    /Users/cpk36/Documents/Git/ingest-api/src/test/datasets_publish_tests.py ../instance/app_dev.cfg https://ingest-api.dev.hubmapconsortium.org BEARER_TOKEN -v
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
parser.add_argument("-v", "--verbose", action="store_true",
                    help='verbose output')

args = parser.parse_args()
os.environ['VERBOSE'] = str(args.verbose)

config = parse_cfg(args.cfg_file)

if urlparse(args.ingest_url).hostname in ['127.0.0.1', 'localhost']:
    local_execution = True
print(f"local_execution: {local_execution}")

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

vprint("BEGIN Processing Datasets with Parents test case...")
with neo4j_driver_instance.session() as neo4j_session:
    query_derived: str = query_derived_str()
    rval = neo4j_session.run(query_derived).data()
    if len(rval) == 0:
        eprint(f"Neo4J query returned no records; query: {query_derived}")
        exit()

    dataset_uuid: str = rval[0]['ds_uuid']
    dataset_group_name: str = rval[0].get('ds_group_name')
    dataset_data_access_level: str = rval[0].get('ds_data_access_level')

    if dataset_data_access_level == "protected":
        full_protected_path: str = f"'{protected_path}/{dataset_group_name}/{dataset_uuid}'"
        vprint(f'Full protected path: {full_protected_path}')
        metadata_json_path: str = f"'{full_protected_path[1:-1]}/metadata.json'"
        vprint(f'Metadata json path: {metadata_json_path}')
        secondary_analysis_path: str = f"'{full_protected_path[1:-1]}/secondary_analysis.h5ad'"
        vprint(f'Secondary Analysis path: {secondary_analysis_path}')

        if local_execution:
            mkdir_p(full_protected_path)
            os.system(f"touch {secondary_analysis_path}")
            rm_f(metadata_json_path)
        else:
            print(f"mkdir -p {full_protected_path}")
            setfacl_cmd: str = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PROTECTED, full_protected_path, False, True)
            setfacl_cmd = setfacl_cmd.replace("''", "'")
            print(setfacl_cmd)
            print(f"touch {secondary_analysis_path}")
            print(f"rm -rf {metadata_json_path}")
            input("Please execute the above commands on the PSC server, and then press Enter to continue...")
    elif dataset_data_access_level == "consortium":
        full_consortium_path: str = f"'{consortium_path}/{dataset_group_name}/{dataset_uuid}'"
        vprint(f'Full consortium path: {full_consortium_path}')
        full_public_path: str = os.path.join(public_path, dataset_uuid)
        vprint(f'Full public path: {full_public_path}')
        metadata_json_path: str = os.path.join(full_public_path, 'metadata.json')
        vprint(f'Metadata json path: {metadata_json_path}')
        secondary_analysis_path: str = f"'{full_consortium_path[1:-1]}/secondary_analysis.h5ad'"
        vprint(f'Secondary Analysis path: {secondary_analysis_path}')

        if local_execution:
            mkdir_p(full_consortium_path)
            mkdir_p(public_path)
            os.system(f"touch {secondary_analysis_path}")
            copy_path: str = os.path.join(full_public_path, dataset_uuid)
            rm_f(copy_path)
            rm_f(metadata_json_path)
        else:
            print(f"mkdir -p {full_consortium_path}")
            setfacl_cmd: str = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_CONSORTIUM, full_consortium_path, False, True)
            setfacl_cmd = setfacl_cmd.replace("''", "'")
            print(setfacl_cmd)
            print(f"touch {secondary_analysis_path}")
            print(f"rm -rf {metadata_json_path}")
            input("Please execute the above commands on the PSC server, and then press Enter to continue...")

    eprint(f"For this test the metadata.json file SHOULD NOT be found {metadata_json_path}")
    publish_and_check(dataset_uuid, metadata_json_path[1:-1])
vprint("END Processing Datasets with Parents test case...")

vprint("BEGIN Processing Protected test case...")
with neo4j_driver_instance.session() as neo4j_session:
    query_protected: str = query_str('protected')
    rval = neo4j_session.run(query_protected).data()
    if len(rval) == 0:
        eprint(f"Neo4J query returned no records; query: {query_protected}")
        exit()

    dataset_uuid: str = rval[0]['ds_uuid']
    dataset_group_name: str = rval[0].get('ds_group_name')

    full_protected_path: str = f"'{protected_path}/{dataset_group_name}/{dataset_uuid}'"
    vprint(f'Full protected path: {full_protected_path}')
    metadata_json_path: str = f"'{full_protected_path[1:-1]}/metadata.json'"
    vprint(f'Metadata json path: {metadata_json_path}')
    secondary_analysis_path: str = f"'{full_protected_path[1:-1]}/secondary_analysis.h5ad'"
    vprint(f'Secondary Analysis path: {secondary_analysis_path}')

    if local_execution:
        mkdir_p(full_protected_path)
        os.system(f"touch {secondary_analysis_path}")
        rm_f(metadata_json_path)
    else:
        print(f"mkdir -p {full_protected_path}")
        setfacl_cmd: str = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PROTECTED, full_protected_path, False, True)
        setfacl_cmd = setfacl_cmd.replace("''", "'")
        print(setfacl_cmd)
        print(f"touch {secondary_analysis_path}")
        print(f"rm -rf {metadata_json_path}")
        input("Please execute the above commands on the PSC server, and then press Enter to continue...")

    publish_and_check(dataset_uuid, metadata_json_path[1:-1])
vprint("END Processing Protected test case...")

vprint("BEGIN Processing Consortium test case...")
with neo4j_driver_instance.session() as neo4j_session:
    query_consortium: str = query_str('consortium')
    rval = neo4j_session.run(query_consortium).data()
    if len(rval) == 0:
        eprint(f"Neo4J query returned no records; query: {query_consortium}")
        exit()

    dataset_uuid: str = rval[0]['ds_uuid']
    dataset_group_name: str = rval[0].get('ds_group_name')

    full_consortium_path: str = f"'{consortium_path}/{dataset_group_name}/{dataset_uuid}'"
    vprint(f'Full consortium path: {full_consortium_path}')
    full_public_path: str = os.path.join(public_path, dataset_uuid)
    vprint(f'Full public path: {full_public_path}')
    metadata_json_path: str = os.path.join(full_public_path, 'metadata.json')
    vprint(f'Metadata json path: {metadata_json_path}')
    secondary_analysis_path: str = f"'{full_consortium_path[1:-1]}/secondary_analysis.h5ad'"
    vprint(f'Secondary Analysis path: {secondary_analysis_path}')

    if local_execution:
        mkdir_p(full_consortium_path)
        mkdir_p(public_path)
        os.system(f"touch {secondary_analysis_path}")
        copy_path: str = os.path.join(full_public_path, dataset_uuid)
        rm_f(copy_path)
        rm_f(metadata_json_path)
    else:
        print(f"mkdir -p {full_consortium_path}")
        setfacl_cmd: str = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_CONSORTIUM, full_consortium_path, False, True)
        setfacl_cmd = setfacl_cmd.replace("''", "'")
        print(setfacl_cmd)
        # These directories should already exist on the server...
        # print(f"mkdir -p {public_path}")
        # setfacl_cmd = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PUBLIC, public_path, False, True)
        # setfacl_cmd = setfacl_cmd.replace("''", "'")
        # print(setfacl_cmd)
        print(f"touch {secondary_analysis_path}")
        print(f"rm -rf {metadata_json_path}")
        input("Please execute the above commands on the PSC server, and then press Enter to continue...")

    publish_and_check(dataset_uuid, metadata_json_path)
vprint("END Processing Consortium test case...")

neo4j_driver_instance.close()
print("Done!")
