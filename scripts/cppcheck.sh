#!/usr/bin/env bash
# Build cppcheck Docker image on first use, then run analysis.
set -e

IMAGE="tethered-cppcheck"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building cppcheck Docker image (first run only)..."
    docker build -t "$IMAGE" -f- . <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends cppcheck >/dev/null && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["cppcheck"]
EOF
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src "$IMAGE" \
    --error-exitcode=1 \
    --enable=warning,performance,portability \
    --suppress=missingIncludeSystem \
    --suppress=missingReturn:src/tethered/_guardian.c \
    "$@"
