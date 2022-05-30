FROM centos:7

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=${USER_UID}

COPY library-scripts/*.sh /tmp/library-scripts/
COPY assets/vomses /etc/vomses
COPY assets/vomsdir /etc/grid-security/vomsdir/
COPY assets/EGI-trustanchors.repo /etc/yum.repos.d/

RUN bash /tmp/library-scripts/provide-user.sh ${USERNAME} ${USER_UID} ${USER_GID} \
 && bash /tmp/library-scripts/provide-deps.sh
