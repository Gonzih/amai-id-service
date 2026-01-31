FROM rust:1.83-slim as builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy actual source and docs
COPY src ./src
COPY skill.md integration.md llms.txt ./

# Build for release
RUN touch src/main.rs && cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/id-service /app/id-service

# Create data directory
RUN mkdir -p /data

ENV HOST=0.0.0.0
ENV PORT=8080
ENV DATA_DIR=/data
ENV RUST_LOG=id_service=info,tower_http=info

EXPOSE 8080

CMD ["/app/id-service"]
