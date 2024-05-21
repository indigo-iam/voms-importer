# VOMS importer

This is a python script that can be used to import data from a VOMS Admin
VO into an IAM organization.

## Devcontainer support

For those who use VSCode, there is support for a remote Devcontainer, which
comes preconfigured with the test VOMS at `meteora.cloud.cnaf.infn.it`.

Note (and beware) that `$HOME/.globus` and `$HOME/.config/oidc-agent`
are mounted from the host.

To run the `vomsimporter` script, you first need to obtain an admin
VOMS proxy with `voms-proxy-init` and an admin access token with
`oidc-token`.

### Running the importer

This is an example to import users from the `test.vo` hosted in [meteora](https://meteora.cloud.cnaf.infn.it:8443), into [iam-dev](https://iam-dev.cloud.cnaf.infn.it).

Pre-requisites
* being an admin of [meteora](https://meteora.cloud.cnaf.infn.it:8443)
* being an admin of [iam-dev](https://iam-dev.cloud.cnaf.infn.it)
* the X.509 certificate linked to the VOMS admin has to be the same as for the IAM admin
* having a local oidc-configuration (generated with Centos7) whith at least the following scopes allowed: `openid iam:admin.read iam:admin.write scim:read scim:write proxy:generate`

Define the following environment variables:

```
OIDC_AGENT_ALIAS=<your-client-alias>
OIDC_AGENT_SECRET=<your-client-secret>
IAM_ENDPOINT=https://iam-dev.cloud.cnaf.infn.it
IAM_HOST=iam-dev.cloud.cnaf.infn.it
VOMS_HOST=meteora.cloud.cnaf.infn.it
VOMS_VO=test.vo
X509_USER_PROXY=/tmp/x509up_u1000
```

Initialize your admin credentials with

```
$ ./docker/init-credentials.sh
```

Run the importer with

```
python vomsimporter.py --vo ${VOMS_VO} --voms-host ${VOMS_HOST} --iam-host ${IAM_HOST} --skip-duplicate-accounts-checks --username-attr nickname --debug --voms-port 8443
```