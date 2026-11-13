FROM qmcgaw/gluetun:v3.41.1@sha256:1a5bf4b4820a879cdf8d93d7ef0d2d963af56670c9ebff8981860b6804ebc8ab AS tunnel

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:088a01637f22908632ba09018be2e0b516f2fa6f7869c191d29491139db43c78 AS observer
WORKDIR /app
COPY api/observe-vpn-exit.mjs api/update-network-data.mjs /app/
ENTRYPOINT ["/nodejs/bin/node", "/app/observe-vpn-exit.mjs"]
