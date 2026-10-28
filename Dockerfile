FROM python:3.12-alpine3.23@sha256:e0e17c55a255d32e515d3ae66577578f2a439ebe92cd4a8b69fc29421bbdba7d AS builder
RUN apk upgrade --no-cache && apk add --no-cache build-base cmake ninja openssl-dev git
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt ./
RUN python -m pip install --require-hashes -r requirements.txt
COPY security/toolchain.json security/toolchain.json
COPY scripts/bootstrap.py scripts/bootstrap.py
RUN python scripts/bootstrap.py

FROM python:3.12-alpine3.23@sha256:e0e17c55a255d32e515d3ae66577578f2a439ebe92cd4a8b69fc29421bbdba7d
RUN apk upgrade --no-cache && apk add --no-cache libcrypto3 libssl3 libstdc++
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
