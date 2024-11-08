FROM lukemathwalker/cargo-chef:latest as chef
WORKDIR /app

FROM chef AS planner

COPY node node
COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY node node
COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/mpc-node mpc-node
CMD [ "./mpc-node", "start" ]
