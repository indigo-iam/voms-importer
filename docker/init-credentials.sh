#!/bin/bash
set -e

check_vars()
{
    var_names=("$@")
    for var_name in "${var_names[@]}"; do
        [ -z "${!var_name}" ] && echo "$var_name is unset." && var_unset=true
    done
    [ -n "$var_unset" ] && exit 1
    return 0
}

IAM_ENDPOINT=${IAM_ENDPOINT}
PROXY_CERT_LIFETIME_SECS=${PROXY_CERT_LIFETIME_SECS:-3600}

check_vars IAM_ENDPOINT OIDC_AGENT_ALIAS OIDC_AGENT_SECRET

eval $(oidc-agent --no-autoload)
oidc-add --pw-cmd='echo $OIDC_AGENT_SECRET' ${OIDC_AGENT_ALIAS}

client_config=$(mktemp)
chmod 600 ${client_config}

oidc-add --pw-cmd='echo $OIDC_AGENT_SECRET' -p ${OIDC_AGENT_ALIAS} > ${client_config}
client_id=$(jq -r .client_id ${client_config})
client_secret=$(jq -r .client_secret ${client_config})
rm -f ${client_config}

BT=$(oidc-token -s proxy:generate ${OIDC_AGENT_ALIAS})
proxyresponse=$(mktemp)
chmod 600 ${proxyresponse}

set +e

curl -s -XPOST -H "Authorization: Bearer ${BT}" \
        -d client_id=${client_id} \
        -d client_secret=${client_secret} \
        -d lifetimeSecs=${PROXY_CERT_LIFETIME_SECS} \
        ${IAM_PROXYCERT_ENDPOINT} > ${proxyresponse}

if [ $? -ne 0 ]; then
    echo "Error requesting proxy certificate"
    cat ${proxyresponse}
    exit 1
fi

set -e 

identity=$(jq -r .identity ${proxyresponse})
proxy_file=$(echo /tmp/x509up_u$(id -u))

touch ${proxy_file}
chmod 600 ${proxy_file}

jq -r .certificate_chain ${proxyresponse} > ${proxy_file}
rm -f ${proxyresponse}

export X509_USER_PROXY=${proxy_file}

echo
echo "A proxy certificate for identity:"
echo
echo ${identity}
echo
echo "has been saved to:"
echo
echo ${proxy_file}

voms-proxy-info -all

BT=$(oidc-token -s openid ${OIDC_AGENT_ALIAS})
BEARER_TOKEN_FILE=/tmp/bt_u$(id -u)
touch ${BEARER_TOKEN_FILE} && chmod 600 ${BEARER_TOKEN_FILE}
echo ${BT} > ${BEARER_TOKEN_FILE}
