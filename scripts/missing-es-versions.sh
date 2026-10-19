#!/usr/bin/env bash
# Print, as a JSON array, the Elasticsearch releases (>= minEsVersion) that the GitHub release
# for the current pluginVersion has no zip for yet. Needs gh, authenticated.
set -euo pipefail
cd "$(dirname "$0")/.."
prop() { sed -n "s/^$1=//p" plugin/gradle.properties; }
PLUGIN_VERSION=$(prop pluginVersion)
MIN=$(prop minEsVersion)

released=$(gh api --paginate 'repos/elastic/elasticsearch/releases?per_page=100' \
  --jq '.[] | select(.prerelease | not) | .tag_name' | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p')
# already published, e.g. ingest-splunk-hec-0.2.4-es9.5.4.zip → 9.5.4
built=$(gh release view "v${PLUGIN_VERSION}" --json assets --jq '.assets[].name' 2>/dev/null \
  | sed -n "s/^ingest-splunk-hec-${PLUGIN_VERSION}-es\(.*\)\.zip$/\1/p" || true)

# the build compiles against these; true once both are on Maven Central
maven_has() {
  local a
  for a in elasticsearch plugin/x-pack-core; do
    curl -sfI -o /dev/null "https://repo.maven.apache.org/maven2/org/elasticsearch/$a/$1/${a##*/}-$1.pom" || return 1
  done
}

for v in $released; do
  # keep v >= MIN
  [ "$(printf '%s\n%s\n' "$MIN" "$v" | sort -V | head -1)" = "$MIN" ] || continue
  grep -qxF "$v" <<<"$built" && continue
  # Maven Central can lag the GitHub release by hours; leave it for the next daily run
  maven_has "$v" || { echo "skipping $v: not on Maven Central yet" >&2; continue; }
  echo "$v"
done | sort -V | jq -Rnc '[inputs]'
