#!/bin/bash

set -e

function install_igtf_ca() {
  yum install -y ca-policy-egi-core
  cp /etc/grid-security/certificates/*.pem /etc/pki/ca-trust/source/anchors/
  update-ca-trust
}

if [ $UID = 0 ]; then
  install_igtf_ca
  exit $?
fi

sudo $0
