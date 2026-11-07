#!/usr/bin/env bash
# Builds the API, domain-updater and network-updater images and smoke-tests each against
# the live public sources. Shared by PR CI and the publish workflow so both test the same thing.
# Usage: api/build-images.sh <api-tag> <domain-updater-tag> <network-updater-tag>
# Optional env: ARCH (amd64|arm64, default host), VERSION and GITHUB_SHA (image labels).
set -euo pipefail
api=$1 updater=$2 network=$3
build() {
    docker buildx build --load --provenance=false ${ARCH:+--platform "linux/$ARCH"} \
        --label "org.opencontainers.image.version=${VERSION:-dev}" \
        --label "org.opencontainers.image.revision=${GITHUB_SHA:-local}" "$@" .
}
run() { docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges "$@"; }
out="$(mktemp -d)"
chmod 777 "$out"
trap 'rm -rf "$out"' EXIT

build -f api/Dockerfile -t "$api"
node api/test.mjs --image "$api"

build --build-arg "API_IMAGE=$api" -f api/updater.Dockerfile -t "$updater"
run -v "$out:/out" "$updater" --output /out/domains.json
node -e 'const d = require(process.argv[1]); if (d.version !== 1 || d.sources.length < 7) process.exit(1)' "$out/domains.json"
run --entrypoint /nodejs/bin/node -v "$out:/out" "$updater" /app/update-country-data.mjs --output /out/country.mmdb
test -s "$out/country.mmdb"

build -f api/Dockerfile --target network-updater -t "$network"
run -v "$out:/out" "$network" --output /out/network.json
docker run --rm --read-only --network none --cap-drop=ALL -v "$out:/out:ro" "$api" --validate-network-data /out/network.json
