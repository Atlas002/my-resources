#!/bin/bash
set -e

# This script will be executed on the first startup of each new container with the "my-resources" feature enabled.
# Arbitrary code can be added in this file, in order to customize Exegol (dependency installation, configuration file copy, etc).
# It is strongly advised **not** to overwrite the configuration files provided by exegol (e.g. /root/.zshrc, /opt/.exegol_aliases, ...), official updates will not be applied otherwise.

# Exegol also features a set of supported customization a user can make.
# The /opt/supported_setups.md file lists the supported configurations that can be made easily.

mkdir -p /workspace/{outputs,downloads,uploads,tools}
xhost local: 2>/dev/null || true

# Background the slow stuff — log it so you can check later
(
    sudo apt update
    pipx install aliasr
    pipx install devious-winrm
    [ ! -d /opt/my-resources/tools/PrivHound ] && \
        git clone https://github.com/dazzyddos/PrivHound /opt/my-resources/tools/PrivHound
) >/var/log/exegol/user_setup_async.log 2>&1 &
