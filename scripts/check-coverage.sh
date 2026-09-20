#!/bin/sh

set -eu

profile=${1:-coverage.out}
if [ "$#" -gt 0 ]; then
  shift
fi
minimum=${1:-45.0}
if [ "$#" -gt 0 ]; then
  shift
fi

if [ ! -s "$profile" ]; then
  echo "coverage profile is missing or empty: $profile" >&2
  exit 1
fi

check_floor() {
  label=$1
  coverage=$2
  floor=$3
  awk -v label="$label" -v coverage="$coverage" -v minimum="$floor" 'BEGIN {
  if (coverage + 0 < minimum + 0) {
    printf "%s coverage %.1f%% is below the %.1f%% floor\n", label, coverage, minimum > "/dev/stderr"
    exit 1
  }
  printf "%s coverage %.1f%% meets the %.1f%% floor\n", label, coverage, minimum
}'
}

coverage=$(awk 'NR > 1 {
  total += $2
  if ($3 > 0) covered += $2
} END {
  if (total > 0) printf "%.6f", 100 * covered / total
}' "$profile")
if [ -z "$coverage" ]; then
  echo "could not read total coverage from: $profile" >&2
  exit 1
fi
check_floor "total" "$coverage" "$minimum"

for requirement in "$@"; do
  case "$requirement" in
    *=*) ;;
    *)
      echo "invalid package coverage requirement: $requirement" >&2
      exit 1
      ;;
  esac
  package=${requirement%%=*}
  floor=${requirement#*=}
  if [ -z "$package" ] || [ -z "$floor" ]; then
    echo "invalid package coverage requirement: $requirement" >&2
    exit 1
  fi

  package_coverage=$(awk -v target="$package" 'NR > 1 {
    file = $1
    sub(/:[0-9].*$/, "", file)
    package = file
    sub(/\/[^/]+$/, "", package)
    suffix = substr(package, length(package) - length(target) + 1)
    separator = substr(package, length(package) - length(target), 1)
    if (package == target || (suffix == target && separator == "/")) {
      total += $2
      if ($3 > 0) covered += $2
    }
  } END {
    if (total > 0) printf "%.6f", 100 * covered / total
  }' "$profile")
  if [ -z "$package_coverage" ]; then
    echo "package has no coverage statements: $package" >&2
    exit 1
  fi
  check_floor "$package" "$package_coverage" "$floor"
done
