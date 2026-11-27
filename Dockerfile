# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder
WORKDIR /usr/src/rustscan-rs

# Build dependencies against a dummy main so they are cached until
# Cargo.toml / Cargo.lock change.
RUN cargo init --bin --name rustscan-rs
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked && rm -rf src

COPY src ./src
COPY templates ./templates
# COPY keeps host mtimes, which can be older than the dummy build.
RUN touch src/main.rs && cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
COPY --from=builder /usr/src/rustscan-rs/target/release/rustscan-rs /usr/local/bin/rustscan-rs
# Grant only CAP_NET_RAW (for --syn) via a file capability, so the scanner
# can run as an unprivileged user. Docker's default capability set includes
# NET_RAW; setcap's package is removed again to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && setcap cap_net_raw+ep /usr/local/bin/rustscan-rs \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home rustscan
USER rustscan
ENTRYPOINT ["rustscan-rs"]
CMD ["--help"]
