# HuBMAP Data Ingest API

A restful web service exposing calls needed for the [Ingest UI](https://github.com/hubmapconsortium/ingest-ui) React application. The API is documented [here](https://smart-api.info/registry?q=5a6bea1158d2652743c7a201fdb1c44d).

## Flask app configuration

This application is written in Flask and it includes an **app.cfg.example** file in the `instance` directory.  Copy the file and rename it **app.cfg** and modify  with the appropriate information.

## Standalone local development

This assumes you are developing the code with the Flask development server and you have access to the remote neo4j database.

### Install dependencies

````
sudo pip3 install -r requirements.txt
````

Note: if you need to use a modified version of the [HuBMAP commons] dependency, download the code and make changes, then install the dependency using `src/requirements_dev.txt` and make sure the local file system path is specified correctly.

### Start Flask development server

````
cd src
export FLASK_APP=app.py
export FLASK_ENV=development
flask run
````

This code runs by default on port 5000. You can change the port using a `-p` or `--port` switch at command line. For instance:

````
flask run -p 5001
````

## Docker development and deployment environments

We have the following 5 development and deployment environments:

* localhost - all the services will be deployed with docker containers including sample Neo4j and sample MySQL are running on the same localhost listing on different ports, without globus data
* dev - all services except ingest-api will be running on AWS EC2 with SSL certificates, Neo4j and MySQL are dev versions on AWS, and ingest-api(and another nginx) will be running on PSC with domain and globus data
* test - similar to dev with a focus on testing and connects to Neo4j and MySQL test versions of database
* stage - as similar to the production environment as it can be.
* prod - similar to test but for production settings with production versions of Neo4j and MySQL

### Localhost development

This option allows you to setup all the pieces in a containerized environment with docker and docker-compose. This requires to have the [HuBMAP Gateway](https://github.com/hubmapconsortium/gateway) running locally before starting building this docker compose project. Please follow the [instructions](https://github.com/hubmapconsortium/gateway#workflow-of-setting-up-multiple-hubmap-docker-compose-projects). It also requires the Gateway project to be configured accordingly.

### Remote deployment

In localhost mode, all the docker containers are running on the same host machine. However, the ingest-api will be deployed on a separare host machine for dev, test, stage, and prod mode due to different deployment requirements. 

There are a few configurable environment variables to keep in mind:

- `COMMONS_BRANCH`: build argument only to be used during image creation. We can specify which [commons](https://github.com/hubmapconsortium/commons) branch to use during the image creation. Default to master branch if not set or null.
- `HOST_UID`: the user id on the host machine to be mapped to the container. Default to 1000 if not set or null.
- `HOST_GID`: the user's group id on the host machine to be mapped to the container. Default to 1000 if not set or null.

We can set and verify the environment variable like below:

````
export COMMONS_BRANCH=devel
echo $COMMONS_BRANCH
````

Note: Environment variables set like this are only stored temporally. When you exit the running instance of bash by exiting the terminal, they get discarded. So for rebuilding the docker image, we'll need to make sure to set the environment variables again if necessary.

````
Usage: ./ingest-api-docker.sh [localhost|dev|test|stage|prod] [check|config|build|start|stop|down]
````

Before we go ahead to start building the docker image, we can do a check to see if the required configuration file is in place:

````
cd docker
./ingest-api-docker.sh dev check
````

We can also validate and view the details of corresponding compose file:

````
./ingest-api-docker.sh dev config
````

Building the docker images and starting/stopping the contianers require to use docker daemon, you'll probably need to use `sudo` in the following steps. If you don’t want to preface the docker command with sudo, add users to the docker group:

````
sudo usermod -aG docker $USER
````

Then log out and log back in so that your group membership is re-evaluated. If testing on a virtual machine, it may be necessary to restart the virtual machine for changes to take effect.

To build the docker image of ingest-api:

````
./ingest-api-docker.sh dev build
````

To start up the ingest-api container (including nginx on the same container):

````
./ingest-api-docker.sh dev start
````

And stop the running container by:

````
./ingest-api-docker.sh dev stop
````

You can also stop the running container and remove it by:

````
./ingest-api-docker.sh dev down
````

### Updating API Documentation

The documentation for the API calls is hosted on SmartAPI.  Modifying the `ingest-api-spec.yaml` file and commititng the changes to github should update the API shown on SmartAPI.  SmartAPI allows users to register API documents.  The documentation is associated with this github account: api-developers@hubmapconsortium.org. 
