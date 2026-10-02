FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system syncd && useradd --system --gid syncd --home /var/lib/keys-keeper-syncd syncd
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    python -m pip install --no-cache-dir --no-index --find-links=/wheels keys-keeper && \
    mkdir -p /var/lib/keys-keeper-syncd && \
    chown syncd:syncd /var/lib/keys-keeper-syncd && \
    chmod 0700 /var/lib/keys-keeper-syncd

USER syncd
VOLUME ["/var/lib/keys-keeper-syncd"]
EXPOSE 8787
ENTRYPOINT ["keys-keeper-syncd"]
CMD ["--host", "0.0.0.0", "--port", "8787", "--allow-non-loopback"]
