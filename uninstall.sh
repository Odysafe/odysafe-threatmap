#!/bin/bash
# Uninstall Odysafe ThreatMap with one confirmation.
set -Eeuo pipefail

readonly PROJECT_NAME="odysafe-threatmap"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly VENV_DIR="${SCRIPT_DIR}/.venv"
readonly USER_BIN_DIR="${HOME}/.local/bin"
readonly DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/${PROJECT_NAME}"
readonly CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/${PROJECT_NAME}"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/${PROJECT_NAME}"

ASSUME_YES=false
for argument in "$@"; do
    case "${argument}" in
        --yes|-y) ASSUME_YES=true ;;
        *) printf '[ERROR] Unknown option: %s\n' "${argument}" >&2; exit 2 ;;
    esac
done

remove_command() {
    local path="$1" expected="$2"
    if [[ -L "${path}" && "$(readlink -- "${path}")" == "${expected}" ]]; then
        rm -- "${path}"
    fi
}

remove_path() {
    local path="$1"
    [[ -e "${path}" || -L "${path}" ]] && rm -rf -- "${path}"
}

main() {
    printf '\n\033[1mOdysafe ThreatMap\033[0m\n'
    printf '\033[2mSafe removal\033[0m\n\n'
    if [[ "${ASSUME_YES}" == false ]]; then
        printf 'Remove Odysafe ThreatMap, environments, settings, data, and caches? [y/N]: '
        read -r answer || exit 0
        [[ "${answer}" =~ ^[Yy]([Ee][Ss])?$ ]] || { printf 'Uninstallation cancelled.\n'; exit 0; }
    fi

    remove_command "${USER_BIN_DIR}/odysafe" "${VENV_DIR}/bin/odysafe"
    remove_command "${USER_BIN_DIR}/odysafe-threatmap" "${VENV_DIR}/bin/odysafe-threatmap"
    remove_path "${VENV_DIR}"
    remove_path "${SCRIPT_DIR}/venv"
    remove_path "${SCRIPT_DIR}/env"
    remove_path "${SCRIPT_DIR}/.env"
    remove_path "${SCRIPT_DIR}/.cache"
    remove_path "${SCRIPT_DIR}/.pytest_cache"
    remove_path "${SCRIPT_DIR}/.ruff_cache"
    remove_path "${SCRIPT_DIR}/.mypy_cache"
    remove_path "${SCRIPT_DIR}/htmlcov"
    remove_path "${SCRIPT_DIR}/odysafe-output"
    remove_path "${SCRIPT_DIR}/.coverage"
    remove_path "${SCRIPT_DIR}/coverage.xml"
    remove_path "${DATA_DIR}"
    remove_path "${CACHE_DIR}"
    remove_path "${CONFIG_DIR}"
    find "${SCRIPT_DIR}" -maxdepth 1 -type f -name '.env.*' -delete
    find "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/tests" -type d -name '__pycache__' -prune -exec rm -rf -- {} + 2>/dev/null || true
    find "${SCRIPT_DIR}" -maxdepth 1 -type f \( -name '*.log' -o -name '.~lock.*' -o -name '~$*.xlsx' \) -delete
    printf '\n\033[32m✓\033[0m Odysafe ThreatMap removed\n\n'
}

main "$@"
