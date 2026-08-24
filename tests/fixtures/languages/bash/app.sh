#!/usr/bin/env bash
set -euo pipefail

source "./lib/common.sh"
source "./lib/logging.sh"

readonly APP_NAME="sample-app"
readonly APP_VERSION="1.0.0"

log_info "Starting $APP_NAME v$APP_VERSION"

cleanup() {
    local dir="$1"
    log_info "Cleaning up $dir"
    rm -rf "$dir"
}

validate_input() {
    local input="$1"
    if [[ -z "$input" ]]; then
        log_error "Input cannot be empty"
        return 1
    fi
    echo "$input" | grep -qE '^[a-zA-Z0-9_]+$'
}

main() {
    local target="${1:-.}"
    log_info "Processing target: $target"

    if validate_input "$target"; then
        echo "Valid input: $target"
    else
        log_error "Invalid input"
        exit 1
    fi
}

main "$@"
