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

### Installing the importer

**`vomsimporter` requires a Python 2.7 environment as some of its dependencies are available
only for Python 2.** The following Python modules are required and can be installed from
EL7 RPMs:

- ldap (from OS repository)
- voms-admin-client
- python2-zsi (from UMD-4 repository)

In addition it is necessary to build the executable `dn_converter` from
`docker/rfc2253/rfc2253.cpp` and move it to the path (or add its path to `PATH`
environment variable). The command to build the executable (see also the source file) is:

```
g++ -std=c++11 rfc2253.cpp -lcrypto -o dn_converter
```

You also need to have access to the `grid-proxy-init` command. Alternatively, you can use this command on another server where it is available and copy the proxy file in `/tmp` on the machine where you run `vomsimporter`.

### Running the importer

This is an example to import users from the `test.vo` hosted in [meteora](https://meteora.cloud.cnaf.infn.it:8443), into [iam-dev](https://iam-dev.cloud.cnaf.infn.it).

Pre-requisites
* be an admin of [meteora](https://meteora.cloud.cnaf.infn.it:8443)
* be an admin of [iam-dev](https://iam-dev.cloud.cnaf.infn.it)
* the X.509 certificate linked to the VOMS admin has to be the same as for the IAM admin
* have a local oidc-configuration (generated with Centos7) whith at least the following scopes allowed: `openid iam:admin.read iam:admin.write scim:read scim:write proxy:generate`
* Load a proxy certificate into INDIGO IAM with a lifetime long enough to complete the VOMS
migration (or you will have to refresh it once it is expired). This is done by
clicking on button `Add managed proxy certificate` and pasting the contents of your grid proxy.
To get a 1 week grid proxy, use the following command: 

```
grid-proxy-init -valid 240:0
```

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

This will initialize a proxy from the certificate loaded in INDIGO IAM and create a token.

Run the importer with

```
python vomsimporter.py --vo ${VOMS_VO} --voms-host ${VOMS_HOST} --iam-host ${IAM_HOST} --skip-duplicate-accounts-checks --username-attr nickname --debug --voms-port 8443
```

If you have SSL errors running this command, you can use `curl` to validate that everything
is ok in your configuration. After obtaining a proxy with the command `grid-proxy-init`
(the proxy build by `init-credentials` does not work with `curl`), enter the following
command (`/path/to/user/certificate` is the certificate used to generate the proxy in
PEM format):

```
curl --cert /tmp/x509up_u1000  --cacert /path/to/user/certificate --capath /etc/grid-security/certificates/  https://meteora.cloud.cnaf.infn.it/voms/test.vo
```

Once you have fixed the problems with the `curl` command, try again to run `vomsimporter`. If it still fails, try to add the option `--insecure` which disables SSL certificate verification.
