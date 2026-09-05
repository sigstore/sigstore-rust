#!/bin/bash
# Check normal dependencies; Cargo failures must not look like a clean tree.
set -euo pipefail
metadata=$(cargo metadata --no-deps --format-version 1)
for package in $(echo "$metadata" | jq -r '.packages[].name'); do
    features=$(echo "$metadata" | jq -r --arg package "$package" '
        .packages[] | select(.name == $package) | .features | keys |
        map(select(. == "native-tls" or . == "tuf" or . == "fetch" or . == "cache")) | join(",")
    ')
    args=(--package "$package" --locked --no-default-features --edges normal --prefix none)
    if [ -n "$features" ]; then
        args+=(--features "$features")
    fi
    tree=$(cargo tree "${args[@]}")
    if grep -q '^rustls v' <<< "$tree"; then
        echo "FAIL: $package pulls in rustls without its rustls feature" >&2
        exit 1
    fi
    echo "OK: $package"
done
