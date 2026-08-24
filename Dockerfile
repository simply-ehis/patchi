# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm AS builder

LABEL maintainer="patchi"
LABEL description="Patchi hosted mode — live application monitoring guard"

WORKDIR /app

# Build-time deps for tree-sitter / scikit-learn compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Layer caching: install runtime deps before copying source
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir "$(python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); deps=d['project']['dependencies']; extras=d['project']['optional-dependencies'].get('web',[]); print(' '.join(deps + extras))")"

# Now copy source and install the package itself (no deps — already done above)
COPY patchi/ patchi/
RUN pip install --no-cache-dir --no-deps .


# ── Runtime stage ──
FROM python:3.11-slim-bookworm

WORKDIR /app

# Only runtime — no gcc/g++
COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app

RUN mkdir -p /data/.patchi/hosted

VOLUME ["/data"]

ENV PATCHI_ROOT=/data

EXPOSE 4321

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:4321/health').status == 200 else 1)"

ENTRYPOINT ["patchi"]
CMD ["hosted", "daemon", "--guard"]
