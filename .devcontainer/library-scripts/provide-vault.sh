#!/bin/bash -e

cat /etc/yum.repos.d/CentOS-Vault.repo \
  | sed -n -e '/# C7.8.2003/,$p'       \
  | sed -e 's/7.8.2003/7.9.2009/g' > CentOS-Vault.repo

mv CentOS-Vault.repo /etc/yum.repos.d/CentOS-Vault.repo

yum-config-manager -y --disable base extras updates
yum-config-manager -y --enable C7.9.2009-base C7.9.2009-extras C7.9.2009-updates
