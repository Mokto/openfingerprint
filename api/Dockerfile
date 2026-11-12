FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS build
WORKDIR /build
COPY api/Cargo.toml api/Cargo.lock api/build.rs ./
COPY api/proto ./proto
COPY api/src ./src
COPY api/migrations ./migrations
COPY api/data ./data
ENV CARGO_BUILD_JOBS=2
RUN set -eu; \
    cargo vendor --locked --versioned-dirs /vendor > /tmp/vendor.toml; \
    target="$(rustc -vV | awk '$1 == "host:" {print $2}')"; \
    cargo tree --frozen --config /tmp/vendor.toml --target "$target" --edges normal,build --prefix none --format '{p}' > /tmp/dependency-tree; \
    awk 'NR > 1 {print $1 "-" substr($2, 2)}' /tmp/dependency-tree | sort -u > /tmp/dependencies; \
    test -s /tmp/dependencies; \
    mkdir -p /out/licenses/dependencies; \
    (cd /vendor; while IFS= read -r crate; do \
        find "$crate" -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'COPYRIGHT*' -o -iname 'NOTICE*' -o -iname 'UNLICENSE*' \) \
            -print -exec cp --parents -t /out/licenses/dependencies {} + > /tmp/license-files; \
        if ! test -s /tmp/license-files; then \
            case "$crate" in \
                buffa-descriptor-*) donor="$(ls -d buffa-[0-9]* | head -n 1)" ;; \
                connectrpc-reflection-*) donor="$(ls -d connectrpc-[0-9]* | head -n 1)" ;; \
                *) donor= ;; \
            esac; \
            test -n "$donor" -a -s "$donor/LICENSE" || { printf 'Missing license files for %s\n' "$crate" >&2; exit 1; }; \
            mkdir -p "/out/licenses/dependencies/$crate"; \
            cp "$donor/LICENSE" "/out/licenses/dependencies/$crate/LICENSE"; \
        fi; \
    done < /tmp/dependencies); \
    cp -a "$(rustc --print sysroot)/share/doc/rust" /out/licenses/rust; \
    cp Cargo.lock /out/licenses/Cargo.lock; \
    cp data/domains.json /out/licenses/domain-data.json; \
    nice -n 15 cargo build --release --frozen --config /tmp/vendor.toml; \
    cp target/release/openfingerprint-api /out/openfingerprint-api
COPY LICENSE /out/licenses/openfingerprint-api/LICENSE

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:088a01637f22908632ba09018be2e0b516f2fa6f7869c191d29491139db43c78 AS network-updater
LABEL org.opencontainers.image.source="https://github.com/Mokto/openfingerprint" \
      org.opencontainers.image.description="Refreshes licensed local network intelligence for OpenFingerprint" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /out/openfingerprint-api /usr/local/bin/openfingerprint-api
COPY --from=build /out/licenses /usr/share/licenses/openfingerprint-api
COPY api/update-network-data.mjs /app/update-network-data.mjs
ENV OPENFINGERPRINT_API_BINARY=/usr/local/bin/openfingerprint-api
USER 65532:65532
ENTRYPOINT ["/nodejs/bin/node", "/app/update-network-data.mjs"]

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
LABEL org.opencontainers.image.source="https://github.com/Mokto/openfingerprint" \
      org.opencontainers.image.description="Browser verification and open-data domain/network checks" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/doc/ca-certificates/copyright /usr/share/licenses/openfingerprint-api/ca-certificates/copyright
COPY --from=build /out/openfingerprint-api /usr/local/bin/openfingerprint-api
COPY --from=build /out/licenses /usr/share/licenses/openfingerprint-api
ENV OPENFINGERPRINT_LISTEN_ADDR=0.0.0.0:8180
EXPOSE 8180 8443
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/openfingerprint-api"]
