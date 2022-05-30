# VOMS importer

This is a python script that can be used to import data from a VOMS Admin
VO into an IAM organization.

## Devcontainer support

For those who use VSCode, there is support for a remote Devcontainer, which
comes preconfigured with the test VOMS at `vgrid02.cnaf.infn.it`.

Note (and beware) that `$HOME/.globus` and `$HOME/.config/oidc-agent`
are mounted from the host.

To run the `vomsimporter` script, you first need to obtain an admin
VOMS proxy with `voms-proxy-init` and an admin access token with
`oidc-token`.
