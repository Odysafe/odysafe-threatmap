#!/bin/bash
# Install Odysafe ThreatMap with working user commands and minimal interaction.
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly VENV_DIR="${SCRIPT_DIR}/.venv"
readonly USER_BIN_DIR="${HOME}/.local/bin"
NO_LAUNCH=false
[[ "${1:-}" == "--no-launch" ]] && NO_LAUNCH=true

fail() { printf '[ERROR] %s\n' "$1" >&2; exit 1; }
ok() { printf '\033[32m✓\033[0m %s\n' "$1"; }

run_with_activity_bar() {
    local label="$1"
    shift
    local log_file process_id status frame position direction bar index
    log_file="$(mktemp -t odysafe-install.XXXXXX)"
    "$@" >"${log_file}" 2>&1 &
    process_id=$!
    frame=0
    position=0
    direction=1
    printf '\n'
    while kill -0 "${process_id}" 2>/dev/null; do
        bar=''
        for ((index = 0; index < 24; index++)); do
            if ((index >= position && index < position + 5)); then
                bar+='█'
            else
                bar+='░'
            fi
        done
        printf '\r\033[36m%s\033[0m  %-38s \033[2mworking\033[0m' "${bar}" "${label}"
        ((position += direction)) || true
        if ((position >= 19 || position <= 0)); then
            direction=$((-direction))
        fi
        ((frame++)) || true
        sleep 0.08
    done
    if wait "${process_id}"; then
        status=0
    else
        status=$?
    fi
    printf '\r\033[2K'
    command cat "${log_file}"
    command rm -f -- "${log_file}"
    if ((status != 0)); then
        return "${status}"
    fi
    printf '\033[32m%s\033[0m  %-38s \033[32mdone\033[0m\n' '████████████████████████' "${label}"
}

header() {
    printf '\n\033[1mOdysafe ThreatMap\033[0m\n'
    printf '\033[2mPrivate. Offline. Ready when you are.\033[0m\n\n'
}

find_python() {
    local candidate
    for candidate in python3 python; do
        command -v "${candidate}" >/dev/null 2>&1 || continue
        if "${candidate}" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
            PYTHON="${candidate}"
            return
        fi
    done
    fail "Python 3.11 or newer is required."
}

find_install_target() {
    if [[ -f "${SCRIPT_DIR}/pyproject.toml" && -d "${SCRIPT_DIR}/src/odysafe_threatmap" ]]; then
        INSTALL_TARGET="${SCRIPT_DIR}"
        INSTALL_DESCRIPTION="current source tree"
        return
    fi
    local wheels=("${SCRIPT_DIR}"/dist/odysafe_threatmap-*.whl)
    [[ -f "${wheels[0]}" ]] || fail "No built wheel was found in ${SCRIPT_DIR}/dist."
    ((${#wheels[@]} == 1)) || fail "Multiple wheels found. Keep only the release you want to install."
    INSTALL_TARGET="${wheels[0]}"
    INSTALL_DESCRIPTION="$(basename -- "${INSTALL_TARGET}")"
}

install_package() {
    if command -v uv >/dev/null 2>&1; then
        uv venv --clear "${VENV_DIR}" --python "${PYTHON}"
        if [[ -d "${INSTALL_TARGET}" ]]; then
            uv pip install --reinstall --python "${VENV_DIR}/bin/python" --editable "${INSTALL_TARGET}"
        else
            uv pip install --reinstall --python "${VENV_DIR}/bin/python" "${INSTALL_TARGET}"
        fi
    else
        "${PYTHON}" -m venv --clear "${VENV_DIR}"
        "${VENV_DIR}/bin/python" -m pip install --upgrade pip
        if [[ -d "${INSTALL_TARGET}" ]]; then
            "${VENV_DIR}/bin/python" -m pip install --force-reinstall --editable "${INSTALL_TARGET}"
        else
            "${VENV_DIR}/bin/python" -m pip install --force-reinstall "${INSTALL_TARGET}"
        fi
    fi
}

install_commands() {
    mkdir -p "${USER_BIN_DIR}"
    mkdir -p "${SCRIPT_DIR}/odysafe-input/reports" "${SCRIPT_DIR}/odysafe-input/sigma"
    ln -sfn "${VENV_DIR}/bin/odysafe" "${USER_BIN_DIR}/odysafe"
    ln -sfn "${VENV_DIR}/bin/odysafe-threatmap" "${USER_BIN_DIR}/odysafe-threatmap"
    case ":${PATH}:" in
        *":${USER_BIN_DIR}:"*) ;;
        *) printf '[INFO] Add %s to PATH to run odysafe from any terminal.\n' "${USER_BIN_DIR}" ;;
    esac
}

configure_attack() {
    [[ -t 0 && -t 1 ]] || return 0
    printf '\n\033[1;35m✦  MITRE ATT&CK DATA\033[0m\n'
    printf '\033[2mChoose the intelligence data Odysafe will use offline.\033[0m\n\n'
    printf '  \033[36m1\033[0m  \033[1m↻ Latest official dataset\033[0m   \033[2mBest for most users\033[0m\n'
    printf '  \033[33m2\033[0m  \033[1m↓ Specific release\033[0m         \033[2mExample: 19.2\033[0m\n'
    printf '  \033[31m3\033[0m  Set up later\n\n'
    printf '\033[1;36m›\033[0m Choose [1]: '
    read -r choice
    case "${choice:-1}" in
        1)
            printf '\033[36mNetwork access is required once.\033[0m Download now? [Y/n]: '
            read -r answer
            if [[ ! "${answer}" =~ ^[Nn]([Oo])?$ ]]; then
                printf '\n\033[1;36m↓ Downloading the official ATT&CK bundle\033[0m\n'
                printf '\033[2mReal byte progress is shown below; validation follows automatically.\033[0m\n\n'
                "${VENV_DIR}/bin/odysafe-threatmap" data update
            fi
            ;;
        2)
            printf 'Release \033[2m(example: 19.2)\033[0m: '
            read -r release
            [[ -n "${release}" ]] || { printf '\033[33mNo release entered. Skipped.\033[0m\n'; return; }
            printf '\033[36mNetwork access is required once.\033[0m Download ATT&CK %s? [Y/n]: ' "${release}"
            read -r answer
            if [[ ! "${answer}" =~ ^[Nn]([Oo])?$ ]]; then
                run_with_activity_bar "Downloading and validating ATT&CK ${release}" \
                    "${VENV_DIR}/bin/odysafe-threatmap" data install --release "${release}"
            fi
            ;;
        3)
            printf '\n\033[1;36mℹ  ATT&CK SETUP DEFERRED\033[0m\n\n'
            printf 'Odysafe is installed, but analyses require a local ATT&CK JSON bundle.\n\n'
            printf '\033[1;32mRecommended command:\033[0m\n\n'
            printf '  \033[1;36m%s data update\033[0m\n\n' "${VENV_DIR}/bin/odysafe-threatmap"
            printf 'This downloads the official Enterprise ATT&CK JSON, validates it,\n'
            printf 'and installs it in the correct Odysafe data directory.\n\n'
            printf '\033[1;33mManual wget equivalent:\033[0m\n\n'
            printf '  \033[36mwget -O /tmp/enterprise-attack.json %s\033[0m\n' \
                'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
            printf '  \033[36m%s data install /tmp/enterprise-attack.json\033[0m\n\n' \
                "${VENV_DIR}/bin/odysafe-threatmap"
            printf '\033[33m⚠ Do not download directly into the managed ATT&CK directory.\033[0m\n'
            printf 'The data install command validates the bundle and creates the required manifest.\n'
            ;;
        *) printf '\033[33mUnknown choice. ATT&CK setup skipped.\033[0m\n' ;;
    esac
}

main() {
    header
    find_python
    find_install_target
    printf '\033[2mInstalling from %s…\033[0m\n' "${INSTALL_DESCRIPTION}"
    install_package
    install_commands
    "${VENV_DIR}/bin/odysafe-threatmap" --version
    ok "Installation complete"
    configure_attack
    printf '\n  Start anytime: \033[1m%s/start.sh\033[0m\n' "${SCRIPT_DIR}"
    printf '  Direct command: \033[1modysafe\033[0m\n\n'
    if [[ "${NO_LAUNCH}" == false && -t 0 && -t 1 ]]; then
        printf 'Open Odysafe now? [Y/n]: '
        read -r answer
        [[ ! "${answer}" =~ ^[Nn]([Oo])?$ ]] && exec "${SCRIPT_DIR}/start.sh"
    fi
}

main "$@"
