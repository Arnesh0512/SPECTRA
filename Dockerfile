# Stage 1: Build dependencies and wheels
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Minimal runtime image
FROM python:3.11-slim AS runtime

LABEL maintainer="Security Engineering Team"
LABEL description="Enterprise Cryptographic Discovery & CycloneDX 1.6 CBOM Generator"

# Install runtime utilities (ripgrep for fast regex search, OpenSSL for binary/cert inspection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ripgrep \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

WORKDIR /app

# Copy application source and configurations
COPY pyproject.toml .
COPY cbom_policy.json .
COPY config.example.yaml .
COPY crypto_recon/ ./crypto_recon/

# Install crypto-recon as a package
RUN pip install --no-cache-dir -e .

# Create non-root runner user
RUN useradd -u 10001 -m appuser && \
    chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["crypto-recon"]
CMD ["--help"]