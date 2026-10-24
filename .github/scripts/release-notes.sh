#!/bin/sh
# Prints Markdown release notes for the commits between the previous version tag and the given tag, grouped by type.
set -eu

tag=$1
previous=$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$tag^" 2>/dev/null || true)

git log --no-merges --format='%s (%h)' "${previous:+$previous..}$tag" |
	awk -v previous="$previous" -v tag="$tag" -v repository="${GITHUB_REPOSITORY:-}" '
	/^[a-z]+(\([^)]*\))?!:/ { breaking[++breakingCount] = $0; next }
	/^(deps|ci|docker)(\([^)]*\))?: bump / { dependencies[++dependencyCount] = $0; next }
	/^feat(\([^)]*\))?:/ { features[++featureCount] = $0; next }
	/^(fix|perf)(\([^)]*\))?:/ { fixes[++fixCount] = $0; next }
	{ other[++otherCount] = $0 }

	function section(title, lines, count,    i) {
		if (count == 0) return
		printf "## %s\n\n", title
		for (i = 1; i <= count; i++) printf "- %s\n", lines[i]
		printf "\n"
	}

	END {
		section("Breaking changes", breaking, breakingCount)
		section("Features", features, featureCount)
		section("Fixes", fixes, fixCount)
		section("Other changes", other, otherCount)
		section("Dependencies", dependencies, dependencyCount)
		if (previous != "" && repository != "") {
			printf "**Full changes**: https://github.com/%s/compare/%s...%s\n", repository, previous, tag
		}
	}
'
