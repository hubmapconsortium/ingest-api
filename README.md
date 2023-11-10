# HuBMAP Data Ingest API

A restful web service exposing calls needed for the [Ingest UI](https://github.com/hubmapconsortium/ingest-ui) React application. The API is documented [here](https://smart-api.info/registry?q=5a6bea1158d2652743c7a201fdb1c44d).

## Working with submodule

This repository relies on the [ingest-validation-tools](https://github.com/sennetconsortium/ingest-validation-tools) as a submodule for metadata validation. The
file `.gitmodules` contains the configuration for the URL and specific branch of the submodule that is to be used. Once
you already have cloned this repository and switched to the target branch, to load the latest `ingest-validation-tools` submodule:

```
git submodule update --init --remote
```

## Flask app configuration

This application is written in Flask and it includes an **app.cfg.example** file in the `instance` directory.  Copy the file and rename it **app.cfg** and modify  with the appropriate information.

## Standalone local development

This assumes you are developing the code with the Flask development server and you have access to the remote neo4j database.

### Generate the BUILD file

In the project root directory:

````
./generate-build-version.sh
````

### Install dependencies

Create a new Python 3.x virtual environment:

````
python3 -m venv venv-hm-ingest-api
source venv-hm-ingest-api/bin/activate
````

Upgrade pip:
````
python3 -m pip install --upgrade pip
````

Then install the dependencies with using the `main` branch code of commons:

````
export COMMONS_BRANCH=main
pip install -r requirements.txt
````

### Start the server

Either methods below will run the search-api web service at `http://localhost:5005`. Choose one:

#### Directly via Python

````
python3 app.py
````

#### With the Flask Development Server

````
cd src
export FLASK_APP=app.py
export FLASK_ENV=development
python3 -m flask run -p 5000
````

### Updating API Documentation

The documentation for the API calls is hosted on SmartAPI.  Modifying the `ingest-api-spec.yaml` file and commititng the changes to github should update the API shown on SmartAPI.  SmartAPI allows users to register API documents.  The documentation is associated with this github account: api-developers@hubmapconsortium.org. 
