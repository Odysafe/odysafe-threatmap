#!/bin/bash
# Start the guided Odysafe ThreatMap experience.
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly LOCAL_COMMAND="${SCRIPT_DIR}/.venv/bin/odysafe-threatmap"

if [[ -x "${LOCAL_COMMAND}" ]]; then
    if [[ -d "${SCRIPT_DIR}/src/odysafe_threatmap" ]]; then
        export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
    fi
    exec "${LOCAL_COMMAND}"
fi
if command -v odysafe-threatmap >/dev/null 2>&1; then
    exec odysafe-threatmap
fi
if command -v odysafe >/dev/null 2>&1; then
    exec odysafe
fi

printf '\033[31mUnable to start Odysafe.\033[0m\n'
printf 'Run this first:\n  \033[1m%s/install.sh\033[0m\n\n' "${SCRIPT_DIR}"
exit 1
