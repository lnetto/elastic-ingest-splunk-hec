#!/usr/bin/env bash
# Build + test the plugin in a JDK 21 Gradle container; the zip lands in dist/.
# Target another Elasticsearch version with: ES_VERSION=9.5.5 ./build-plugin.sh
set -euo pipefail
cd "$(dirname "$0")"
rm -rf plugin/build/distributions
docker volume create ingest-splunk-hec-gradle-cache >/dev/null
# a fresh named volume is root-owned; hand it to the calling user
docker run --rm -v ingest-splunk-hec-gradle-cache:/cache --entrypoint chown gradle:8-jdk21 "$(id -u):$(id -g)" /cache
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/cache \
  -v "$PWD":/work -v ingest-splunk-hec-gradle-cache:/cache -w /work/plugin \
  gradle:8-jdk21 gradle --no-daemon -q ${ES_VERSION:+-PesVersion=$ES_VERSION} "${@:-test}" bundlePlugin
mkdir -p dist && rm -f dist/*.zip
cp plugin/build/distributions/*.zip dist/
ls -l dist/*.zip
