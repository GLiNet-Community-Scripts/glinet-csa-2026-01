#!/bin/sh
# Writes src/known-hashes.json: the SHA-256 of every binary in the releases of the
# community's Tailscale and AdGuard Home builds, taken from the checksums.txt of each
# release. The dashboard treats a reported file with one of these fingerprints as a known
# release file and does not list it for review. Run it after a new release, then
# "node build.mjs":
#   sh tools/known-hashes.sh
# A release that was built again keeps only its latest checksums, so an older build of the
# same version is not in the list.
set -eu
cd "$(dirname "$0")/.."
out=src/known-hashes.json
tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.c"' EXIT
for pair in "Tailscale|admonstrator/glinet-tailscale-updater" "AdGuard Home|admonstrator/glinet-adguard-updater"; do
	name=${pair%%|*}; repo=${pair#*|}
	for tag in $(git ls-remote --tags "https://github.com/$repo" | sed 's#.*refs/tags/##' | grep -v '\^{}' | sort -u); do
		curl -fsSL -m 30 -o "$tmp.c" "https://github.com/$repo/releases/download/$tag/checksums.txt" 2>/dev/null || continue
		# "<sha256>  tailscaled-linux-arm64" -> "<sha256> Tailscale v1.2.3 arm64"
		awk -v n="$name" -v t="$tag" 'length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && NF == 2 {
			a = $2; plain = (a ~ /-noupx-/) ? ", not compressed" : ""
			sub(/^.*linux[-_]/, "", a)
			print $1 " " n " " t " " a plain
		}' "$tmp.c" >>"$tmp"
	done
done
[ -s "$tmp" ] || { echo "no checksums fetched" >&2; exit 1; }
{
	printf '{\n'
	sort -u -k1,1 "$tmp" | awk '{ h = $1; $1 = ""; sub(/^ /, ""); gsub(/["\\]/, ""); printf "%s\"%s\": \"%s\"", (NR > 1 ? ",\n" : ""), h, $0 } END { printf "\n" }'
	printf '}\n'
} >"$out"
echo "$out: $(grep -c '": "' "$out") fingerprints"
