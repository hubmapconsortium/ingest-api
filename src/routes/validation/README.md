# Validating metadata 

## Validate using form data
`POST /metadata/validate`

### Payload (Form Data):
```
metadata: (binary) # this is the TSV upload
entity_type: Source
sub_type: murine
```

### Sample response:
The response will contain the `metadata` to be stored in db, and the `pathname` which can be used for reference and revalidation purposes
```
{ code: 200
metadata: [{bedding: "Aspen chip", cage_enhancements: "Nestlets",…}]
pathname: "cr46sq7pbn594v2btqst/example_source_mouse_metadata.tsv"}
```

## Validate using json
It is possible validate a file by passing a `pathname`.
This is useful for revalidating a tsv file and comparing its metadata response to another.
Actually done in `entity-api` to verify that the posted `metadata` from the portal-ui is valid.

The following is an example using `curl`.
``` bash
curl --verbose --request POST \
 --url ${INGESTAPI_URL}/metadata/validate \
 --header "Content-Type: application/json" \
 --header "Accept: application/json" \
 --header "Authorization: Bearer ${TOKEN}" \
 --data '{"pathname":"example_sample_block_metadata.tsv", "entity_type":"Sample", "sub_type": "Block"}'
echo
```

### Testing locally

In order to set this up to run locally you will need to change
the `FILE_UPLOAD_TEMP_DIR` and `FILE_UPLOAD_DIR` lines in `instance/app.cfg`.
```
FILE_UPLOAD_TEMP_DIR = '{full-path}/Git/ingest-api/src/test/file_upload/temp_dir'
FILE_UPLOAD_DIR = '{full-path}/Git/ingest-api/src/test/file_upload/dir'
```
You will need to copy a TSV file (named in the json `pathname` data above) to the `FILE_UPLOAD_TEMP_DIR` directory.

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

To support CEDAR the primary thing that needs to be done is to create a API token
by signing in via GitHub [here](https://cedar.metadatacenter.org/) then navigating to
[profile](https://cedar.metadatacenter.org/profile) to get the key.

The token is then added to `instance/app.cfg` as follows:
```commandline
# CEDAR API KEY, get one at: https://cedar.metadatacenter.org/
CEDAR_API_KEY = ''
```

## Submodule and Virtual Environment

This section will talk about installing the Git submodule
as well as building the virtual environment for local testing.

### Adding the Git Submodule

To install the submodule execute the following at the top level of the project
```commandline
$ git submodule update --init --remote
$ git submodule add --name ingest_validation_tools
```

This will install a `.gitmodules` file at the project top level.
```commandline
[submodule "ingest_validation_tools"]
	path = src/routes/validation/ingest_validation_tools
	url = https://github.com/hubmapconsortium/ingest-validation-tools
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
