# Docker Deployment on PSC

The ingest-api is deployed on the PSC hive infrastructure to handle various file system activities. 

PSC uses Puppet service to achieve the following goals:

- Separation of concerns: mainly for the infrastructure-specific configurations (managed via the [PSC HuBMAP GitLab repos](https://gitlab.psc.edu/hubmap), PSC VPN and account are required)
- Operational efficiency: in terms of migration and recovery

## Workflow

Across DEV/TEST/PROD:

- Puppet doesn't pull any GitHub or GitLab code to the VMs, it only handles file syncing on the local file system
- Manually pull the `ingest-api` GitHub code on PSC VM, manually build the image with the script
- Manually pull the corresponding `ingest-api_config` GitLab updates if any, Puppet copies the config files to desired directories every 30 minutes
