#-------------------------------------------------------------------------------
# Builder
#-------------------------------------------------------------------------------

FROM rust:1.85.0 AS builder

RUN update-ca-certificates

# Create appuser
ENV USER=appuser
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /app

COPY ./ .

RUN cargo build --release

#-------------------------------------------------------------------------------
# Final image
#-------------------------------------------------------------------------------

FROM debian:bookworm-slim

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /app

# Copy our build
COPY --from=builder /app/target/release/vcservice ./

# Use an unprivileged user.
USER appuser:appuser
EXPOSE 8080
CMD ["/app/vcservice"]
