#HuBMAP AirFlow Mock Service
The HuBMAP AirFlow Mock Service is a simple standalone web service for use when developing locally when installing the [full AirFlow services that are used in HuBMAP](https://github.com/hubmapconsortium/ingest-pipeline) is not feasible.

###Configuration and Running
To configure and run:
- Clone the [ingest-api](https://github.com/hubmapconsortium/ingest-api) repo from GitHub
- Configure the `src/instance/app.cfg` file to point to the correct services/database being used for testing/development.  This is the main configuration file used for the ingest-api, the mock service uses it directly.  If `app.cfg` doesn't exist copy `app.cfg.example` in the same directory and provide the appropriate values for all properties.
- Install the python dependencies in `src/requirements.txt` (use of a [python virtual environment](https://docs.python.org/3/tutorial/venv.html) is encouraged).
- Run the mock service by changing directory to `ingest-api/mock-airflow` then run with the command: `python3 app.py`

NOTE: By default the service, as configured an run here, will default to running on http://localhost:8000/.  If also running the ingest-api locally the `INGEST_PIPELINE_URL` in app.cfg should be set to `INGEST_PIPELINE_URL = 'http://localhost:8000/api/hubmap'`

###Using the Mock Data Upload Validate Method
The method, `mock-service/api/hubmap/uploads/<upload-uuid>/validate` method mirrors the same AirFlow method which:
- validates the referenced Upload
- sets the status of the Upload and a validation message depending on the results of the validation

The mock method looks for the file `mock_run.json` in the local Upload directory (something like `/hive/hubmap/data/protected/Group Name/<upload-uuid>/`). `mock_run.json` contains three fields as described here:

- **mock_processing_time_seconds** - Required parameter.  The number of seconds that the method waits until resetting setting the status of the Upload.
- **new_status_message** - Optional parameter: If present will be used to set the `validation_message` of the referenced Upload. If not present the validation message will remain the same.
- **new_status** - Optional parameter: If present will be used to set the status of the referenced Upload.  If not set the status will remain the same.

Example mock_run.json:
```
{
      "mock_processing_time_seconds": 20,
      "new_status_message": "new message",
      "new_status": "Invalid"
}
```
