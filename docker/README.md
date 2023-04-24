# Deployment on PSC

The ingest-api is deployed on the PSC hive infrastructure to handle various file system activities. A sub request is made against the Auth Gateway on AWS via nginx.

Environment specific docker-compose yaml files and Nginx conf files are stored and managed via the [PSC HuBMAP Gitlab repos](https://gitlab.psc.edu/hubmap), which require PSC VPN and login to access.

## PSC DEV

The DEV environment is very different from TEST/PROD in that we can build the docker image manually, no Puppet service is being used.

## PSC TEST/PROD:

- TEST will use the `latest` docker image tag
- PROD will use an explicit version tag.
- Sometimes the code changes will require corresponding `app.cfg` updates (mainly adding new items), I'll commit to the Gitlab repo
- For PROD, you will have to add a file, `DEPLOY_INGEST_API`, to the `/opt/repository/{hostname}-{env}` directory so that Puppet knows to actually deploy things.
Puppet service will pull the docker image and the Gitlab changes, and should redeploy the containers. The new config will be placed in the appropriate places, by Puppet, prior to the redeployment.
