FROM rust:1.99.1-slim-bookworm@sha256:ed2c95ca377d6571b124b05e75e01207973ded639dce7d5542eb7bcd797e32aa AS build
WORKDIR /build
COPY api/Cargo.toml api/Cargo.lock ./
COPY api/src ./src
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
        test -s /tmp/license-files || { printf 'Missing license files for %s\n' "$crate" >&2; exit 1; }; \
    done < /tmp/dependencies); \
    cp -a "$(rustc --print sysroot)/share/doc/rust" /out/licenses/rust; \
    cp Cargo.lock /out/licenses/Cargo.lock; \
    nice -n 15 cargo build --release --frozen --config /tmp/vendor.toml; \
    cp target/release/openfingerprint-api /out/openfingerprint-api
COPY LICENSE /out/licenses/openfingerprint-api/LICENSE

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
LABEL org.opencontainers.image.source="https://github.com/Mokto/openfingerprint" \
      org.opencontainers.image.description="Experimental stateless OpenFingerprint profile verifier" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /out/openfingerprint-api /usr/local/bin/openfingerprint-api
COPY --from=build /out/licenses /usr/share/licenses/openfingerprint-api
ENV OPENFINGERPRINT_LISTEN_ADDR=0.0.0.0:8180
EXPOSE 8180
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/openfingerprint-api"]
