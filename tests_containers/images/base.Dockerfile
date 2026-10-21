# The image of a container suite.  Built by tests_containers/run.py with the
# repository root as the build context:
#
#   docker build -f tests_containers/images/base.Dockerfile \
#       --build-arg PYTHON_TAG=3.13 --build-arg SUITE=uvicorn -t tethered-ct/uvicorn:py3.13 .
#
# base.Dockerfile.dockerignore, next to this file, keeps the context small.
# The layers go from what changes least to what changes most: system packages,
# the suite's requirements, tethered, the tests.

ARG PYTHON_TAG=3.13

# ── builder: a wheel of tethered from the working tree ─────────────────
# The full image has the compiler the C extension needs.
#
# Every pip install of both stages takes the releases of a week ago, as the
# lockfiles of the repository do: pinned or not, and the build requirements
# of what is built from source (setuptools here), which pip installs in a
# process of its own.  A pin younger than that fails the build.  The cutoff
# is a build argument, so RUN sees it in its environment and the containers
# that run the tests do not.  pip takes a span from 26.1, and ignores the
# variable before: an image whose pip is older (24.0 on 3.11, 25.0.1 on
# 3.12) first gets 26.2.1, a release older than the week, where a floor such
# as "pip>=26.1" would take the newest pip.
FROM python:${PYTHON_TAG} AS builder
RUN python -c "import pip, sys; sys.exit(tuple(map(int, pip.__version__.split('.')[:2])) < (26, 1))" \
 || pip install --no-cache-dir --disable-pip-version-check pip==26.2.1
ARG PIP_UPLOADED_PRIOR_TO=P7D
WORKDIR /src
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE ./
COPY src ./src
RUN pip wheel . --no-deps --no-cache-dir --disable-pip-version-check --wheel-dir /wheels

# ── runtime: what a deployment looks like ─────────────────────────────
FROM python:${PYTHON_TAG}-slim AS runtime

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# iproute2: the world's addresses.  procps: ps and pkill, for whoever debugs a run.
# APT_PACKAGES and COMPILER come from the suite's suite.toml.
ARG APT_PACKAGES=""
ARG COMPILER=0
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 procps ${APT_PACKAGES} \
        $(if [ "${COMPILER}" = "1" ]; then echo gcc g++ make libc6-dev; fi) \
 && rm -rf /var/lib/apt/lists/*

# The releases of a week ago, as in the builder above.
RUN python -c "import pip, sys; sys.exit(tuple(map(int, pip.__version__.split('.')[:2])) < (26, 1))" \
 || pip install pip==26.2.1
ARG PIP_UPLOADED_PRIOR_TO=P7D

# With UNPINNED=1 the "==version" of every requirement is dropped and pip takes
# the latest release of a week ago.  UNPINNED_STAMP is the date, so that this
# is done again at most once a day and not served from the build cache for ever.
ARG UNPINNED=0
ARG UNPINNED_STAMP=""
COPY tests_containers/harness/requirements.txt /tc/requirements/harness.txt
RUN if [ "${UNPINNED}" = "1" ]; then \
        echo "unpinned ${UNPINNED_STAMP}"; \
        sed -E -i 's/^([A-Za-z0-9._-]+(\[[^]]*\])?)==[^;# ]+/\1/' /tc/requirements/harness.txt; \
    fi \
 && pip install -r /tc/requirements/harness.txt

ARG SUITE
COPY tests_containers/suites/${SUITE}/requirements.txt /tc/requirements/suite.txt
RUN if [ "${UNPINNED}" = "1" ]; then \
        echo "unpinned ${UNPINNED_STAMP}"; \
        sed -E -i 's/^([A-Za-z0-9._-]+(\[[^]]*\])?)==[^;# ]+/\1/' /tc/requirements/suite.txt; \
    fi \
 && pip install -r /tc/requirements/suite.txt

# A regular install of the wheel: tethered.pth lands in site-packages, as it
# does for a user.  The build fails here if the bootstrap or the C extension
# is missing.
COPY --from=builder /wheels /wheels
COPY tests_containers/images/verify_install.py /tc/verify_install.py
RUN pip install --no-deps /wheels/tethered-*.whl \
 && python /tc/verify_install.py \
 && pip freeze > /tc/pip-freeze.txt

COPY tests_containers/harness /tc/harness
COPY tests_containers/suites/${SUITE} /tc/suites/${SUITE}

# "python -m harness" finds the package through the working directory.  There
# is deliberately no PYTHONPATH here: the helpers decide what a process under
# test can import.
ENV TC_IN_CONTAINER=1 \
    TC_SUITE=${SUITE}
WORKDIR /tc
ENTRYPOINT ["python", "-m", "harness"]
