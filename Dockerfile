# Pin the multi-architecture manifest so a tag move cannot silently change the base.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS builder
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md LICENSE ./
COPY scanner ./scanner
COPY data ./data
# Build runtime wheels only; test tooling and source reports stay out of the image.
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
LABEL org.opencontainers.image.title="VulnScanner" \
      org.opencontainers.image.description="Authorization-first bounded web and network scanner" \
      org.opencontainers.image.version="0.6.0" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VULNSCAN_STATE_DIR=/var/lib/vulnscanner
RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /app /var/lib/vulnscanner /reports \
    && chown scanner:scanner /var/lib/vulnscanner /reports \
    && chmod 0700 /var/lib/vulnscanner /reports
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels authorized-vulnscanner==0.6.0 \
    && rm -rf /wheels
WORKDIR /app
COPY --chown=10001:10001 config.yaml allowlist.txt ./
USER 10001:10001
ENTRYPOINT ["vulnscan"]
# Starting the container never starts an unrequested scan.
CMD ["--help"]
