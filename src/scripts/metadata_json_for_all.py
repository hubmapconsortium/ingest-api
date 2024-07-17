import argparse
import os
import sys
import json

from hubmap_sdk import EntitySdk
from hubmap_commons import neo4j_driver
from hubmap_commons.hubmap_const import HubmapConst
sys.path.append(os.getcwd())
from ingest_file_helper import IngestFileHelper


def eprint(*eargs, **ekwargs) -> None:
    print(*eargs, file=sys.stderr, **ekwargs)


def vprint(*vargs, **vkwargs) -> None:
    if 'VERBOSE' in os.environ and os.environ['VERBOSE'] == 'True':
        print(*vargs, file=sys.stderr, **vkwargs)


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


def mkdir_p(path: str) -> None:
    cmd: str = f"mkdir -p '{path}'"
    vprint(f"mkdir_p: {cmd}")
    os.system(cmd)


def obj_to_dict(obj) -> dict:
    """
    Convert the obj[ect] into a dict, but deeply.

    Note: The Python builtin 'vars()' does not work here because of the way that some of the classes
    are defined.
    """
    return json.loads(
        json.dumps(obj, default=lambda o: getattr(o, '__dict__', str(o)))
    )


def entity_json_dumps(entity_instance: EntitySdk, dataset_uuid: str) -> str:
    """
    Because entity and the content of the arrays returned from entity_instance.get_associated_*
    contain user defined objects we need to turn them into simple python objects (e.g., dicts, lists, str)
    before we can convert them wth json.dumps.

    Here we create an expanded version of the entity associated with the dataset_uuid and return it as a json string.
    """
    entity = obj_to_dict(entity_instance.get_entity_by_id(dataset_uuid))
    entity['organs'] = obj_to_dict(entity_instance.get_associated_organs_from_dataset(dataset_uuid))
    entity['samples'] = obj_to_dict(entity_instance.get_associated_samples_from_dataset(dataset_uuid))
    entity['donors'] = obj_to_dict(entity_instance.get_associated_donors_from_dataset(dataset_uuid))

    json_object = json.dumps(entity, indent=4)
    json_object += '\n'
    return json_object


class RawTextArgumentDefaultsHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawTextHelpFormatter
):
    pass


# Notes:
#
# On DEV the log file for ingest-api is at: /opt/repositories/vm001-dev/ingest-api/log/uwsgi-ingest-api.log
#
# Also on DEV or PROD you must create a virtual environment to run in:
# cd /opt/repositories/vm001-dev/ingest-api/src/scripts
# python3 -m pip install --upgrade pip
# python3 -m venv venv; source venv/bin/activate
# pip3 install -r ../requirements.txt
# cd ..
# python3 scripts/metadata_json_for_all.py instance/app.cfg <token> -v -d
# deactivate; rm -rf scripts/venv

# https://docs.python.org/3/howto/argparse.html
parser = argparse.ArgumentParser(
    description='''
    "Script to write metadata.json file "for all existing Published, processed datasets including
    Central Processed, Lab Processed and EPIC (External) processed datasets" Issue #576.
    
    This script should be run directly on PSC hardware to create the metadata.json file in
    the same fashion as is created at publication time as described in the ingest-api card
    "generate metadata.json file at publication" Issue #375.
    ''',
    formatter_class=RawTextArgumentDefaultsHelpFormatter)
parser.add_argument('cfg_file',
                    help='Configuration file with required information such as base data directory'
                         '(used to calculate absolute path to dataset), any API service urls needed,'
                         'any Neo4j connection information needed, any passwords, tokens, etc...')
parser.add_argument('bearer_token',
                    help='groups_token from Local Storage when logged into ingest-dev (see above)')
parser.add_argument("-l", "--local_execution", action="store_true",
                    help='When run locally create directories if they do not exist')
parser.add_argument("-d", "--dev_execution", action="store_true",
                    help='When run on DEV create directories if they do not exist')
parser.add_argument("-v", "--verbose", action="store_true",
                    help='Verbose output')

args = parser.parse_args()
os.environ['VERBOSE'] = str(args.verbose)
if args.local_execution and args.dev_execution:
    eprint("Can only specify --local_execution OR --dev_execution but not both!")
    os.exit(1)

config = parse_cfg(args.cfg_file)

# The new neo4j_driver (from commons package) is a singleton module
# This neo4j_driver_instance will be used for application-specific neo4j queries
# as well as being passed to the schema_manager
try:
    neo4j_driver_instance = neo4j_driver.instance(config['NEO4J_SERVER'],
                                                  config['NEO4J_USERNAME'],
                                                  config['NEO4J_PASSWORD'])

    vprint("Initialized neo4j_driver module successfully :)")
except Exception:
    eprint("Failed to initialize the neo4j_driver module")
    os.exit(1)

entity_instance = EntitySdk(token=args.bearer_token, service_url=config['ENTITY_WEBSERVICE_URL'])
ingest_helper = IngestFileHelper(config)

with neo4j_driver_instance.session() as neo_session:
    # For all existing Published, processed datasets
    # including Central Processed, Lab Processed and EPIC (External) processed datasets, generate a metadata.json file.
    q_published_processed_datasets = (
        "MATCH (ds:Dataset {status: 'Published', entity_type: 'Dataset'})<-[:ACTIVITY_OUTPUT]-(a:Activity) "
        "WHERE a.creation_action IN ['Central Process', 'Lab Process', 'External Process'] "
        "RETURN "
        "ds.uuid as uuid, ds.group_uuid as group_uuid, ds.data_access_level as data_access_level")
    rvals = neo_session.run(q_published_processed_datasets).data()

    for rval in rvals:
        dataset_uuid: str = rval.get('uuid')
        dataset_group_uuid: str = rval.get('group_uuid')
        dataset_data_access_level: str = rval.get('data_access_level')

        ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level,
                                                                dataset_group_uuid, dataset_uuid, False)
        # Since these datasets have already been published, this directory should already exist on the server...
        if args.local_execution or args.dev_execution:
            mkdir_p(ds_path)
        if args.dev_execution:
            facl_cmd: str = ingest_helper.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PROTECTED, ds_path)
            vprint(f"facl_cmd executed: {facl_cmd}")
        md_file = os.path.join(ds_path, "metadata.json")
        json_object = entity_json_dumps(entity_instance, dataset_uuid)
        vprint(f"publish_datastage; writing md_file: '{md_file}'; "
               f"containing ingest_metadata.metadata: '{json_object}'")
        try:
            with open(md_file, "w") as outfile:
                outfile.write(json_object)
        except IOError as ioe:
            eprint(f"Error while writing md_file {md_file}; {ioe}")
            os.exit(1)

neo4j_driver.close()
print('Done!')
