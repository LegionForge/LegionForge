# guardian/Dockerfile
# LegionForge Guardian sidecar — deterministic security enforcement service.
# NO LLM clients, NO GPU required, minimal attack surface.
#
# Build:  docker build -f guardian/Dockerfile -t legionforge-guardian .
# Run:    docker-compose up guardian

FROM python:3.11-slim

# Security: non-root user
RUN addgroup --system guardian && adduser --system --ingroup guardian guardian

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY guardian/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy only what Guardian needs — minimise attack surface.
# Phase G1 note: config/ no longer copied — guardian.py uses env vars only.
# Phase G2 note: this Dockerfile will be superseded by packages/guardian/Dockerfile.
COPY src/security/ /app/src/security/
COPY src/__init__.py /app/src/__init__.py

# Create runtime directories, hand ownership to non-root user.
RUN mkdir -p /app/logs && chown -R guardian:guardian /app

# Make the src package importable without the full project installed
ENV PYTHONPATH=/app

# Non-root execution
USER guardian

# Guardian listens on 9766 (localhost-only binding enforced in compose)
EXPOSE 9766

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9766/health')"

CMD ["uvicorn", "src.security.guardian:app", "--host", "0.0.0.0", "--port", "9766", "--log-level", "info"]
