import argparse
import os
import sys
import json
import ast

from hubmap_commons import neo4j_driver, string_helper
from ingest_file_helper import IngestFileHelper


def eprint(*eargs, **ekwargs):
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


class RawTextArgumentDefaultsHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawTextHelpFormatter
):
    pass


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
parser.add_argument("-l", "--local_execution", action="store_true",
                    help='When run locally create directories if they do not exist')
parser.add_argument("-v", "--verbose", action="store_true",
                    help='Verbose output')

args = parser.parse_args()
os.environ['VERBOSE'] = str(args.verbose)

config = parse_cfg(args.cfg_file)

# The new neo4j_driver (from commons package) is a singleton module
# This neo4j_driver_instance will be used for application-specifc neo4j queries
# as well as being passed to the schema_manager
try:
    neo4j_driver_instance = neo4j_driver.instance(config['NEO4J_SERVER'],
                                                  config['NEO4J_USERNAME'],
                                                  config['NEO4J_PASSWORD'])

    vprint("Initialized neo4j_driver module successfully :)")
except Exception:
    eprint("Failed to initialize the neo4j_driver module")
    os.exit(1)


ingest_helper = IngestFileHelper(config)

with neo4j_driver_instance.session() as neo_session:
    # For all existing Published, processed datasets
    # including Central Processed, Lab Processed and EPIC (External) processed datasets, generate a metadata.json file.
    q_published_processed_datasets = (
        "MATCH (ds:Dataset {status: 'Published', entity_type: 'Dataset'})<-[:ACTIVITY_OUTPUT]-(a:Activity) "
        "WHERE a.creation_action IN ['Central Process', 'Lab Process', 'External Process'] "
        "RETURN "
        "ds.uuid as uuid, ds.group_uuid as group_uuid, ds.data_access_level as data_access_level, "
        "ds.ingest_metadata as ingest_metadata")
    rvals = neo_session.run(q_published_processed_datasets).data()

    for rval in rvals:
        dataset_uuid: str = rval.get('uuid')
        dataset_group_uuid: str = rval.get('group_uuid')
        dataset_data_access_level: str = rval.get('data_access_level')
        dataset_ingest_metadata: str = rval.get('ingest_metadata')

        if dataset_ingest_metadata is not None:
            dataset_ingest_matadata_dict: dict = ast.literal_eval(dataset_ingest_metadata)

            # Save a .json file with the metadata information at the top level directory...
            vprint(f"ingest_matadata: {dataset_ingest_matadata_dict}")
            json_object = json.dumps(dataset_ingest_matadata_dict, indent=4)
            json_object += '\n'
            ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level,
                                                                    dataset_group_uuid, dataset_uuid, False)
            # Since these datasets have already been published, this directory should already exist on the server...
            if args.local_execution:
                mkdir_p(ds_path)
            md_file = os.path.join(ds_path, "metadata.json")
            vprint(f"publish_datastage; writing md_file: '{md_file}'; "
                   f"containing ingest_matadata.metadata: '{json_object}'")
            try:
                with open(md_file, "w") as outfile:
                    outfile.write(json_object)
            except IOError as ioe:
                eprint(f"Error while writing md_file {md_file}; {ioe}")
                os.exit(1)

neo4j_driver.close()
vprint('Done!')
