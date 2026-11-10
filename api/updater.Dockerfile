ARG API_IMAGE=openfingerprint-api:check
FROM ${API_IMAGE} AS api

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:088a01637f22908632ba09018be2e0b516f2fa6f7869c191d29491139db43c78
LABEL org.opencontainers.image.source="https://github.com/Mokto/openfingerprint" \
      org.opencontainers.image.description="Refreshes open domain and country data for the OpenFingerprint API" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=api /usr/local/bin/openfingerprint-api /usr/local/bin/openfingerprint-api
COPY --from=api /usr/share/licenses/openfingerprint-api /usr/share/licenses/openfingerprint-api
COPY LICENSE /usr/share/licenses/openfingerprint-domain-updater/LICENSE
COPY api/update-domain-data.mjs api/update-country-data.mjs /app/
COPY api/data/reviewed-*.json /app/data/
USER 65532:65532
ENTRYPOINT ["/nodejs/bin/node", "/app/update-domain-data.mjs"]
