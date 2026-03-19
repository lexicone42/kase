FROM rust:1.85-alpine AS builder
WORKDIR /app
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/kase /usr/local/bin/kase
ENV KASE_URL=http://localhost:3000
EXPOSE 3000
ENTRYPOINT ["kase"]
CMD ["serve"]
