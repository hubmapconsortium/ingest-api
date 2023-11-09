# Validating metadata 

The following describes the msAPI endpoint for validating metadata.

## Validate using form data

It is possible to upload the file to validate in the form using the appropriate content type.
The following is an example using `curl`.
```
curl --verbose --request POST \
 --url ${INGESTAPI_URL}/metadata/validate \
 --header "Authorization: Bearer ${TOKEN}" \
 --header "Content-Type: multipart/form-data" \
 --form entity_type=Sample \
 --form sub_type=Block \
 --form metadata=@<pathroot>/ingest-api/src/test/data/tsv/example_sample_block_metadata.tsv
```

The response will contain the `code`, `metadata`, and the `pathname` which can be used for reference and revalidation purposes.
```
{"code":200,
"metadata":[{"histological_report":"","notes":"","pathology_distance_unit":"cm","pathology_distance_value":"42","preparation_condition":"frozen in liquid nitrogen","preparation_media":"Methanol","processing_time_unit":"min","processing_time_value":"","quality_criteria":"","sample_id":"SNT479.CJXT.947","source_storage_time_unit":"min","source_storage_time_value":"42","storage_media":"Methanol","storage_method":"frozen in liquid nitrogen","type":"block","version":"1","volume_unit":"mm^3","volume_value":"42","weight_unit":"kg","weight_value":"42"}],
"pathname":"k9zkvnznlbpee7mnvcg3/example_sample_block_metadata.tsv"}
```

## Validate using json
It is possible validate a file by passing a `pathname` of the file on the server.
This is useful for revalidating a tsv file and comparing its metadata response to another.

This is done in `entity-api` to verify that the posted `metadata` from the portal-ui is valid.

The following is an example using `curl`.
``` bash
curl --verbose --request POST \
 --url ${INGESTAPI_URL}/metadata/validate \
 --header "Content-Type: application/json" \
 --header "Accept: application/json" \
 --header "Authorization: Bearer ${TOKEN}" \
 --data '{"pathname":"example_sample_block_metadata.tsv", "entity_type":"Sample", "sub_type": "Block"}'
```

The response returned will be similar to that using `form data`.
```
{"code":200,
"metadata":[{"histological_report":"","notes":"","pathology_distance_unit":"cm","pathology_distance_value":"42","preparation_condition":"frozen in liquid nitrogen","preparation_media":"Methanol","processing_time_unit":"min","processing_time_value":"","quality_criteria":"","sample_id":"SNT479.CJXT.947","source_storage_time_unit":"min","source_storage_time_value":"42","storage_media":"Methanol","storage_method":"frozen in liquid nitrogen","type":"block","version":"1","volume_unit":"mm^3","volume_value":"42","weight_unit":"kg","weight_value":"42"}],
"pathname":"1699555211.465837.tsv"}
```

### Testing locally

In order to test this locally you will need to change
the `FILE_UPLOAD_TEMP_DIR` and `FILE_UPLOAD_DIR` lines in `instance/app.cfg`.
```
FILE_UPLOAD_TEMP_DIR = '{full-path}/Git/ingest-api/src/test/file_upload/temp_dir'
FILE_UPLOAD_DIR = '{full-path}/Git/ingest-api/src/test/file_upload/dir'
```
You will need to copy a TSV file (named in the json `pathname` --data above) to the `FILE_UPLOAD_TEMP_DIR` directory.

Sample TSV files can be found [here](https://github.com/hubmapconsortium/ingest-validation-tools/tree/main/examples/tsv-examples).

### Verify a certain TSV row

If want to validate a certain row in a file, pass `tsv_row` in the data payload.
```
{pathname: "cr46sq7pbn594v2btqst/example_source_mouse_metadata.tsv",
tsv_row: 3,
entity_type: Sample,
sub_type: Block}
```

### Failed Response
Failed responses will return status of `406 Not Acceptable`.
```
{code:406,
description: [0:"Unexpected fields: {'area_value', 'section_thickness_unit', 'section_thickness_value', 'area_unit', 'histological_report', 'section_index_number'}"
1:"Missing fields: {'suspension_enriched_target', 'suspension_entity_number', 'suspension_entity', 'suspension_enriched'}"
2:"In column 13, found \"histological_report\", expected \"suspension_entity\"",…],
name:"Unacceptable Metadata"}
```

## CEDAR

To support
[CEDAR](https://metadatacenter.github.io/cedar-manual/advanced_topics/b2_cedars_api/)
you will need to have a CEDAR API key (see the `About your API Key` section).
You can retrieve the key by
[signing in](https://cedar.metadatacenter.org/) then navigating to
[profile](https://cedar.metadatacenter.org/profile) to get the key.

If you are a new user you will have to register via the `Register`
link on the `signing in` page (see `API Keys` then `KEY`).

The key should then be added to `instance/app.cfg` as follows:
```
# CEDAR API KEY, get one at: https://cedar.metadatacenter.org/
CEDAR_API_KEY = 'your-key-goes-here'
```

## Submodule and Virtual Environment

This section will talk about installing/updating the Git submodule
as well as building the virtual environment for local testing.

### Adding the Git Submodule

To install the submodule execute the following at the top level of the project
```commandline
$ git submodule update --init --remote
$ cd src/routes/validation
$ git submodule add --name ingest_validation_tools
```

This will install a `.gitmodules` file at the project top level.
```
[submodule "ingest_validation_tools"]
	path = src/routes/validation/ingest_validation_tools
	url = https://github.com/hubmapconsortium/ingest-validation-tools
```

### Changing the Submodule Branch

First, change the branch in .gitmodules (if a brnach is specified), then execute the following:

```commandline
$ git submodule update --init --recursive --remote
$ cd src/routes/validation/ingest_validation_tools
$ git pull
$ git checkout main
$ git status
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

### Building a Virtual Environment

To building a virtual environment while upgrading the Git submodule `ingest_validation_tools`
can be done so as follows. Notice that the `requirements.txt` associaged
with the git module must also be installed in the virtual environment.

```commandline
$ deactivate; rm -rf src/env
$ python3 -m venv src/env
$ source src/env/bin/activate
$ python3 -m pip install --upgrade pip
$ git submodule update --init --recursive
$ python3 -m pip install -r src/routes/validation/ingest_validation_tools/requirements.txt
$ python3 -m pip install -r src/requirements.txt
```
