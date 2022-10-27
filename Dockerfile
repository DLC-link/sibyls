FROM rust:1.62 AS builder

WORKDIR /usr/src/sibyls
ADD . .

RUN cargo build --release

FROM debian:buster-slim
COPY --from=builder /usr/src/sibyls/target/release/sibyls /app/sibyls
WORKDIR /app
ENTRYPOINT ["/app/sibyls"]