# The image of the DNS benchmark.  Built by benchmarks/dns_lookups.py with the
# repository root as the build context:
#
#   docker build -f benchmarks/dns_lookups/Dockerfile --build-arg PYTHON_TAG=3.14 \
#       -t tethered-bench-dns:py3.14 .
#
# Dockerfile.dockerignore, next to this file, keeps the context small.  tethered
# goes in as the container suites put it in (tests_containers/images/
# base.Dockerfile): a wheel built from the working tree, installed into the
# slim image like a user's.

ARG PYTHON_TAG=3.14

# ── builder: a wheel of tethered from the working tree ─────────────────
# The full image has the compiler the C extension needs.
FROM python:${PYTHON_TAG} AS builder
WORKDIR /src
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE ./
COPY src ./src
RUN pip wheel . --no-deps --no-cache-dir --disable-pip-version-check --wheel-dir /wheels

# ── runtime: a slim image with the resolvers to measure ──────────────
FROM python:${PYTHON_TAG}-slim AS runtime

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# systemd-resolved: the caching stub of Ubuntu and Fedora hosts, run here
# without systemd.  dnsmasq-base: a caching stub as a container would run one.
# iproute2: the network interface systemd-resolved needs before it forwards.
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd-resolved dnsmasq-base iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY benchmarks/dns_lookups/requirements.txt /bench/requirements.txt
RUN pip install -r /bench/requirements.txt

COPY --from=builder /wheels /wheels
RUN pip install --no-deps /wheels/tethered-*.whl \
 && python -c "import tethered, tethered._guardian; print('tethered', tethered.__version__)"

COPY benchmarks/dns_lookups/*.py /bench/
ARG PYTHON_TAG
ENV BENCH_IMAGE=python:${PYTHON_TAG}-slim
WORKDIR /bench
ENTRYPOINT ["python", "/bench/inside.py"]
