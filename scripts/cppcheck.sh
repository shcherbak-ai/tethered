#!/usr/bin/env bash
# Run cppcheck from a Docker image that holds one pinned release, built from
# the upstream source on first use.  The pre-commit hook is the only caller,
# locally and in CI, so both analyse with the same version.
set -e

# The release and the commit its tag points at.  To upgrade, change both
# (`git ls-remote --tags https://github.com/danmar/cppcheck`): the image is
# named after the version, so the next run builds the new one, and the build
# fails if the commit turns out to be another version.
CPPCHECK_VERSION="2.22.0"
CPPCHECK_COMMIT="a436ca35ed1887bee789765122b65ed2d7a7e045"

IMAGE="tethered-cppcheck:${CPPCHECK_VERSION}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building the cppcheck ${CPPCHECK_VERSION} Docker image (first run only, takes a minute or two)..."
    docker build -t "$IMAGE" \
        --build-arg CPPCHECK_VERSION="$CPPCHECK_VERSION" \
        --build-arg CPPCHECK_COMMIT="$CPPCHECK_COMMIT" \
        -f- . <<'EOF'
FROM ubuntu:24.04 AS build
ARG CPPCHECK_VERSION
ARG CPPCHECK_COMMIT
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        ca-certificates cmake g++ git make >/dev/null && \
    rm -rf /var/lib/apt/lists/*
RUN git init -q /cppcheck && \
    git -C /cppcheck fetch -q --depth 1 https://github.com/danmar/cppcheck "$CPPCHECK_COMMIT" && \
    git -C /cppcheck checkout -q FETCH_HEAD
RUN cmake -S /cppcheck -B /build -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/cppcheck >/dev/null && \
    cmake --build /build --parallel "$(nproc)" >/dev/null && \
    cmake --install /build >/dev/null
RUN test "$(/opt/cppcheck/bin/cppcheck --version)" = "Cppcheck $CPPCHECK_VERSION"

FROM ubuntu:24.04
COPY --from=build /opt/cppcheck /opt/cppcheck
ENTRYPOINT ["/opt/cppcheck/bin/cppcheck"]
EOF
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src "$IMAGE" \
    --error-exitcode=1 \
    --enable=warning,performance,portability \
    --suppress=missingIncludeSystem \
    --suppress=missingReturn:src/tethered/_guardian.c \
    "$@"
