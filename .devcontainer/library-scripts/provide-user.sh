#!/usr/bin/env bash

USERNAME=${1}
USER_UID=${2}
USER_GID=${3}

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo -e 'Script must be run as root. Use sudo, su, or add "USER root" to your Dockerfile before running this script.'
    exit 1
fi

groupadd --gid $USER_GID $USERNAME
useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

yum install -y sudo
echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME
chmod 0440 /etc/sudoers.d/$USERNAME

CODESPACES_BASH="$(cat \
<<'EOF'

# Codespaces bash prompt theme
__bash_prompt() {
    local userpart='`export XIT=$? \
        && [ ! -z "${GITHUB_USER}" ] && echo -n "\[\033[0;32m\]@${GITHUB_USER} " || echo -n "\[\033[0;32m\]\u " \
        && [ "$XIT" -ne "0" ] && echo -n "\[\033[1;31m\]➜" || echo -n "\[\033[0m\]➜"`'
    local gitbranch='`\
        export BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null); \
        if [ "${BRANCH}" = "HEAD" ]; then \
            export BRANCH=$(git describe --contains --all HEAD 2>/dev/null); \
        fi; \
        if [ "${BRANCH}" != "" ]; then \
            echo -n "\[\033[0;36m\](\[\033[1;31m\]${BRANCH}" \
            && if git ls-files --error-unmatch -m --directory --no-empty-directory -o --exclude-standard ":/*" > /dev/null 2>&1; then \
                    echo -n " \[\033[1;33m\]✗"; \
            fi \
            && echo -n "\[\033[0;36m\]) "; \
        fi`'
    local lightblue='\[\033[1;34m\]'
    local removecolor='\[\033[0m\]'
    PS1="${userpart} ${lightblue}\w ${gitbranch}${removecolor}\$ "
    unset -f __bash_prompt
}
__bash_prompt

EOF
)"

USER_RC_PATH="/home/${USERNAME}"

echo "${CODESPACES_BASH}" >> "${USER_RC_PATH}/.bashrc"
echo "export X509_USER_PROXY=/tmp/x509up_u1000" >> "${USER_RC_PATH}/.bashrc"
echo "export REQUESTS_CA_BUNDLE=/etc/grid-security/certificates" >> "${USER_RC_PATH}/.bashrc"
chown ${USERNAME}:${USERNAME} "${USER_RC_PATH}/.bashrc"

echo "Done!"
