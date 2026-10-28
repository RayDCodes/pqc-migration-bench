FROM python:3.12-slim-bookworm@sha256:6dd8b6dab6b3adc7812bab69eca5dbdc1a5cc690ad28306d234ffb4ef8ac9753 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake ninja-build libssl-dev git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt ./
RUN python -m pip install --require-hashes -r requirements.txt
COPY security/toolchain.json security/toolchain.json
COPY scripts/bootstrap.py scripts/bootstrap.py
RUN python scripts/bootstrap.py

FROM python:3.12-slim-bookworm@sha256:6dd8b6dab6b3adc7812bab69eca5dbdc1a5cc690ad28306d234ffb4ef8ac9753
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 && rm -rf /var/lib/apt/lists/*
ARG SOURCE_REVISION=unknown
ENV PATH="/opt/venv/bin:$PATH" \
    OQS_INSTALL_PATH=/app/liboqs-install \
    LD_LIBRARY_PATH=/app/liboqs-install/lib \
    PYTHONDONTWRITEBYTECODE=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    PQC_BENCH_REVISION=$SOURCE_REVISION
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/liboqs-install /app/liboqs-install
COPY src src
USER 10001:10001
ENTRYPOINT ["python", "src/bench.py"]
CMD ["--quick", "--out", "/tmp/smoke.csv"]
