# Deployment on PSC

The ingest-api is deployed on the PSC hive infrastructure to handle various file system activities. A sub request is made against the Auth Gateway on AWS via nginx.

Puppet service is used to achieve the following goals:

- Separation of concerns: mainly for the infrastructure-specific configurations (managed via the [PSC HuBMAP GitLab repos](https://gitlab.psc.edu/hubmap), which require PSC VPN and login to access)
- Operational efficiency: in terms of migration and recovery