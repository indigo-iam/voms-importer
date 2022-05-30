#!/bin/bash -e

curl -s -O https://bootstrap.pypa.io/pip/2.7/get-pip.py
python get-pip.py
pip install requests

# additional repos
yum -y install \
  epel-release \
  https://repo.ius.io/ius-release-el7.rpm

# repo for IGI Test CA
curl -s https://ci.cloud.cnaf.infn.it/view/repos/job/repo_test_ca/lastSuccessfulBuild/artifact/test-ca.repo > /etc/yum.repos.d/test-ca.repo

# repo for oidc-agent
curl -s https://repo.data.kit.edu/data-kit-edu-centos7.repo > /etc/yum.repos.d/data-kit-edu-centos7.repo

# packages
yum -y install \
  https://repo.cloud.cnaf.infn.it/repository/voms-externals-rpm/centos7/python2-zsi-2.1-16.el7.noarch.rpm \
  https://repo.cloud.cnaf.infn.it/repository/voms-rpm-stable/centos7/voms-admin-client-2.0.20-1.el7.noarch.rpm \
  openldap \
  openldap-clients \
  openssl \
  git236 \
  which \
  hostname \
  file \
  nc \
  jq \
  igi-test-ca \
  java-11-openjdk \
  voms-clients-java \
  haveged \
  less \
  rsync \
  ca-policy-egi-core \
  fetch-crl \
  oidc-agent-cli \
  bind-utils
