#!/bin/sh
# Prints every RuntimePolicy document found under examples/ as a single YAML
# stream on stdout, with template placeholders substituted. Discovery is a glob
# so a newly added example directory is covered without editing this suite.
#
# Non-RuntimePolicy documents (workload pods, ConfigMaps, Services) are dropped:
# the CRD-conformance cluster has no daemon, and only schema acceptance matters.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT

for f in "$root"/examples/*.yaml "$root"/examples/*/*.yaml; do
  [ -f "$f" ] || continue
  sed -e 's/ALLOWED_IP/10.0.0.1/g' -e 's/DENIED_IP/10.0.0.2/g' "$f" | awk '
    function emit() {
      if (doc ~ /(^|\n)apiVersion:[ \t]*runtime\.nirmata\.io\/v1alpha1[ \t]*(\n|$)/ &&
          doc ~ /(^|\n)kind:[ \t]*RuntimePolicy[ \t]*(\n|$)/) {
        printf "---\n%s", doc
      }
    }
    /^---[ \t]*$/ { emit(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { emit() }
  ' >>"$rendered"
done

count=$(grep -c '^kind:[ ]*RuntimePolicy[ ]*$' "$rendered" || true)
if [ "${count:-0}" -eq 0 ]; then
  echo "no RuntimePolicy manifests discovered under $root/examples" >&2
  exit 1
fi

cat "$rendered"
