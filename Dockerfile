# Build Stage
FROM rust:1.76-slim-bullseye AS builder

WORKDIR /usr/src/rustscan-rs

# Create a dummy project to cache dependencies
RUN cargo init --bin
COPY Cargo.toml Cargo.lock ./
# Build dependencies (this will cache them as long as toml/lock don't change)
RUN cargo build --release
RUN rm -rf src/

# Now copy actual source code
COPY src ./src
COPY templates ./templates

# Touch main.rs to force a rebuild of the application code, not just dependencies
RUN touch src/main.rs

# Build final release binary
RUN cargo build --release

# Final Stage (minimal runtime)
FROM debian:bullseye-slim

# Install OpenSSL/ca-certificates if required for certain networking/TLS operations
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/rustscan-rs/target/release/rustscan-rs /usr/local/bin/rustscan-rs

# Create a non-root user for security
RUN useradd -m rustscan
USER rustscan

ENTRYPOINT ["rustscan-rs"]
CMD ["--help"]
