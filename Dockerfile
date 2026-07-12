# MnemoCA — FIPS 140-3 enabled build.
#
# Stage 1 builds with the validated Go Cryptographic Module (GOFIPS140) and
# runs the full test suite under FIPS runtime mode. Stage 2 is an interop
# gate: OpenSSL 3.5 must independently verify an ML-DSA certificate chain
# issued by the freshly built binary. Stage 3 is a minimal distroless runtime
# with FIPS mode on by default.
#
# Build (cluster nodes are AMD64):
#   docker build --platform linux/amd64 -t ghcr.io/mnemoshare/mnemoca:dev .

ARG GO_VERSION=1.26
ARG FIPS_MODULE=v1.0.0

FROM golang:${GO_VERSION}-trixie AS build
ARG FIPS_MODULE
ARG VERSION=dev
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath \
    GOFIPS140=${FIPS_MODULE}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Full test suite under FIPS 140-3 runtime mode — the image does not build
# unless everything passes the way it will run.
RUN GODEBUG=fips140=on go test ./...
RUN go build -ldflags "-X github.com/mnemoshare/mnemoca/cmd/mnemoca/cmd.Version=${VERSION}" \
      -o /out/mnemoca ./cmd/mnemoca

# Interop gate: OpenSSL 3.5 (Debian trixie) verifies a pure ML-DSA chain
# issued by the binary we just built. Fails the build on any mismatch with
# RFC 9881 encodings.
FROM debian:trixie-slim AS interop
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mnemoca /usr/local/bin/mnemoca
ENV MNEMOCA_DATA=/tmp/ca MNEMOCA_PASSPHRASE=interop-gate GODEBUG=fips140=on
RUN set -eux; \
    openssl version; \
    mnemoca init --alg ml-dsa-65; \
    mnemoca tenant create interop; \
    mnemoca keygen --alg ml-dsa-65 -o /tmp/leaf.key; \
    mnemoca csr --key /tmp/leaf.key --cn interop.test --dns interop.test -o /tmp/leaf.csr; \
    mnemoca issue --tenant interop --csr /tmp/leaf.csr -o /tmp/chain.pem; \
    csplit -s -z -f /tmp/cert- -b '%d.pem' /tmp/chain.pem '/BEGIN CERTIFICATE/' '{*}'; \
    openssl x509 -in /tmp/cert-0.pem -noout -text | grep -i ml-dsa-65; \
    openssl verify -CAfile /tmp/cert-2.pem -untrusted /tmp/cert-1.pem /tmp/cert-0.pem; \
    mnemoca audit verify; \
    touch /tmp/interop-ok; \
    install -d -o 65532 -g 65532 /out-data

FROM gcr.io/distroless/static-debian12:nonroot
# FIPS 140-3 runtime mode on by default; override GODEBUG to disable.
ENV GODEBUG=fips140=on \
    MNEMOCA_DATA=/data
COPY --from=build /out/mnemoca /mnemoca
# The interop stage must have succeeded for these copies to resolve; /data
# ships owned by nonroot (65532) so anonymous volumes inherit writability.
COPY --from=interop /tmp/interop-ok /tmp/interop-ok
COPY --from=interop --chown=65532:65532 /out-data /data
VOLUME /data
EXPOSE 8443
USER nonroot
ENTRYPOINT ["/mnemoca"]
CMD ["serve"]
