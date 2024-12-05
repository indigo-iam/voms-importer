FROM centos:7 as builder

ADD rfc2253 /root/rfc2253
ADD provide-vault.sh /tmp

RUN bash /tmp/provide-vault.sh && yum -y install gcc-c++ openssl-devel
RUN cd /root/rfc2253 && c++ --version && c++ --std=c++11 -lcrypto -lssl -o dn_converter rfc2253.cpp

FROM centos:7

# Allow customization of test user ID and name
ARG TEST_USER=test
ARG TEST_USER_UID=501

ADD provide-vault.sh /tmp

COPY --from=builder /root/rfc2253/dn_converter /usr/local/bin/dn_converter

ENV TEST_USER $TEST_USER
ENV TEST_USER_UID $TEST_USER_UID

RUN bash /tmp/provide-vault.sh && \
  curl https://bootstrap.pypa.io/pip/2.7/get-pip.py > get-pip.py && \
  python get-pip.py && \
  pip install requests && \
  yum -y install python-ldap && \
  yum -y install https://repo.cloud.cnaf.infn.it/repository/voms-externals-rpm/centos7/python2-zsi-2.1-16.el7.noarch.rpm && \
  yum -y install https://repo.cloud.cnaf.infn.it/repository/voms-rpm-stable/centos7/voms-admin-client-2.0.20-1.el7.noarch.rpm 

RUN yum -y install openldap openldap-clients openssl git which hostname epel-release sudo file wget && \
      echo '%wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
      adduser --uid ${TEST_USER_UID} ${TEST_USER} && \
      usermod -a -G wheel ${TEST_USER} && \
      yum -y install nc jq java-11-openjdk && \
      yum -y install voms-clients-java && \
      yum -y install https://github.com/indigo-dc/oidc-agent/releases/download/v3.3.5/oidc-agent-3.3.5-1.el7.x86_64.rpm && \
      yum -y install haveged && \
      yum clean all && \
      rm -rf /var/cache/yum


ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ADD ./convert_dn /usr/local/bin
ADD ./dn-converter-0.0.1-SNAPSHOT.jar /home/$TEST_USER
COPY ./init-credentials.sh /usr/local/bin/init-credentials.sh
COPY ./vomsimporter.py /usr/local/bin/vomsimporter
RUN chmod 755 /usr/local/bin/vomsimporter
RUN chown $TEST_USER:$TEST_USER /home/$TEST_USER/dn-converter-0.0.1-SNAPSHOT.jar

ENTRYPOINT ["/tini", "--", "/usr/local/bin/vomsimporter"]
CMD ["--help"]

RUN chmod -R go+rwx /home/$TEST_USER
USER $TEST_USER
WORKDIR /home/$TEST_USER
