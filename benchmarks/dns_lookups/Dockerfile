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
#
# Every pip install takes the releases of a week ago, build requirements
# included, as in the images of the container suites (see there): a build
# argument, and pip 26.2.2, by its URL with its hash, where the image's own is
# older (an older pip cannot take the span, or trusts compromised CAs).
FROM python:${PYTHON_TAG} AS builder
RUN python -c "import pip, sys; sys.exit(tuple(map(int, pip.__version__.split('.')[:3])) < (26, 2, 2))" \
 || pip install --no-cache-dir --disable-pip-version-check \
        "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
ARG PIP_UPLOADED_PRIOR_TO=P7D
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

# The releases of a week ago, and pip 26.2.2, as in the builder above.
RUN python -c "import pip, sys; sys.exit(tuple(map(int, pip.__version__.split('.')[:3])) < (26, 2, 2))" \
 || pip install "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
ARG PIP_UPLOADED_PRIOR_TO=P7D

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
