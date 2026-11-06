FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:b8cec4b2f2126ff7bd034ec9ac207ffb3272667dfdc48376e3b035d3270549ba
LABEL org.opencontainers.image.source="https://github.com/Mokto/openfingerprint" \
      org.opencontainers.image.description="Publishes open domain snapshots for the OpenFingerprint API" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY LICENSE /usr/share/licenses/openfingerprint-domain-updater/LICENSE
COPY api/update-domain-data.mjs /app/update-domain-data.mjs
COPY api/data/reviewed-free-subdomains.json api/data/reviewed-domain-disputes.json /app/data/
USER 65532:65532
ENTRYPOINT ["/nodejs/bin/node", "/app/update-domain-data.mjs"]
