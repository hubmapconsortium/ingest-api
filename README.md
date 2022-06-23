# HuBMAP Data Ingest API

A restful web service exposing calls needed for the [Ingest UI](https://github.com/hubmapconsortium/ingest-ui) React application. The API is documented [here](https://smart-api.info/registry?q=5a6bea1158d2652743c7a201fdb1c44d).

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

Then install the dependencies with using the `master` branch code of commons:

````
export COMMONS_BRANCH=master
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


## Docker build for DEV development

There are a few configurable environment variables to keep in mind:

- `COMMONS_BRANCH`: build argument only to be used during image creation when we need to use a branch of commons from github rather than the published PyPI package. Default to master branch if not set or null.
- `HOST_UID`: the user id on the host machine to be mapped to the container. Default to 1000 if not set or null.
- `HOST_GID`: the user's group id on the host machine to be mapped to the container. Default to 1000 if not set or null.

We can set and verify the environment variable like below:

````
export COMMONS_BRANCH=master
echo $COMMONS_BRANCH
````

Note: Environment variables set like this are only stored temporally. When you exit the running instance of bash by exiting the terminal, they get discarded. So for rebuilding the docker image, we'll need to make sure to set the environment variables again if necessary.

```
cd docker
./docker-development.sh [check|config|build|start|stop|down]
```

## Docker build for deployment on TEST/STAGE/PROD

```
cd docker
export INGEST_API_VERSION=a.b.c (replace with the actual released version number)
./docker-deployment.sh [test|stage|prod] [start|stop|down]
```



### Updating API Documentation

The documentation for the API calls is hosted on SmartAPI.  Modifying the `ingest-api-spec.yaml` file and commititng the changes to github should update the API shown on SmartAPI.  SmartAPI allows users to register API documents.  The documentation is associated with this github account: api-developers@hubmapconsortium.org. 
