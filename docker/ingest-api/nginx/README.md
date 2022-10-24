# NGINX

## Running in Container on localhost

These are instructions for starting ingest-api in a Docker container
on local host.

You should remember that ingest-api is the only micro-service that
runs on the PSC machines, because it needs to have access to the file
system at the PSC. So you will need to modify the docker-compose file
to add the directories on your localhost for ingest-api to be able to
process the data.

### Process

In order to build the images you will need to use
````bash
$ cd docker
$ ./docker-development.sh build
````

Next you will need to define some environment variables. For BASE_USER_UID
and BASE_USER_GID use the uid and gid returned from the id command.
For the INGEST_API_VERSION use the string found in the ./VERSION file.
````bash
$ id
uid=298980485(cpk36) gid=731655015 ...
$ export BASE_USER_UID=`id -u`
$ export BASE_USER_GID=`id -g`
$ export INGEST_API_VERSION=`cat ./VERSION`
````

If necessary you may need to stop any running containers created here
using 'docker ps' and then 'docker stop CONTAINER_ID'.

Next you can start up the container using
````bash
$ cd docker
$ docker-compose -f docker-compose.localhost.yml up
````

#### Spatial-api

If you are testing with spatial-api you will need to add it to the
network created in the ingest-api container
````bash
$ docker network connect docker_hubmap spatial-api
$ docker network inspect docker_hubmap
````

