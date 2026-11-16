#!/usr/bin/env bash
# The work of the GitHub Action in action.yml. Inputs arrive as SW_* environment variables, never
# interpolated into this script, so a branch name or note cannot inject a shell command.
set -euo pipefail

cli=(npx --yes "${SW_PACKAGE:?}")
# Tests run the checked-out CLI instead of the published package.
if [ -n "${SW_CLI:-}" ]; then read -r -a cli <<< "$SW_CLI"; fi

# The CLI runs from an empty folder, so an .npmrc in the checkout cannot choose the registry npx
# fetches the package from (and so cannot run its own code with the upload token in reach).
tooldir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/security-watch.XXXXXX")"
trap 'rm -rf "$tooldir"' EXIT
here="$PWD"
abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$here" "$1" ;; esac; }
sw() { (cd "$tooldir" && "${cli[@]}" "$@"); }

count() {
  node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String((d.components??d.packages??(d.sbom&&d.sbom.packages)??[]).length))' "$1"
}

if [ -n "${SW_SBOM_FILE:-}" ]; then
  # An SBOM made by another tool (Trivy, Syft, cdxgen, GitHub): check that Security Watch can read it.
  path="$SW_SBOM_FILE"
  report="$(mktemp)"
  status=0
  sw import-sbom --input "$(abs "$path")" > "$report" || status=$?
  # 2 means "imported, with warnings" (for example operating-system packages); anything else failed.
  if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then exit "$status"; fi
  packages="$(count "$report")"
  warnings="$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).warnings.length))' "$report")"
  rm -f "$report"
  echo "$path: Security Watch reads $packages packages from it ($warnings warnings)."
else
  args=(sbom --project "$(abs "${SW_PROJECT:-.}")" --output "$(abs "${SW_OUTPUT:-security-watch.cdx.json}")")
  [ -n "${SW_SYSTEM_ID:-}" ] && args+=(--system-id "$SW_SYSTEM_ID")
  [ -n "${SW_NAME:-}" ] && args+=(--name "$SW_NAME")
  [ -n "${SW_OWNER:-}" ] && args+=(--owner "$SW_OWNER")
  [ -n "${SW_ENVIRONMENT:-}" ] && args+=(--environment "$SW_ENVIRONMENT")
  [ -n "${SW_NOTE:-}" ] && args+=(--note "$SW_NOTE")
  [ -n "${SW_EXPOSURE:-}" ] && args+=(--exposure "$SW_EXPOSURE")
  [ -n "${SW_CRITICALITY:-}" ] && args+=(--criticality "$SW_CRITICALITY")
  [ "${SW_PRODUCTION:-false}" = "true" ] && args+=(--production)
  sw "${args[@]}"
  path="${SW_OUTPUT:-security-watch.cdx.json}"
  packages="$(count "$path")"
fi

if [ -n "${SW_UPLOAD_URL:-}" ]; then
  if [ -z "${SECURITY_WATCH_INTAKE_TOKEN:-}" ]; then
    echo "upload-url is set but upload-token is empty; pass it from a secret." >&2
    exit 1
  fi
  upload=(upload --input "$(abs "$path")" --url "$SW_UPLOAD_URL")
  # A generated SBOM carries its system ID (lower-cased by sbom); only another tool's SBOM needs it.
  [ -n "${SW_SBOM_FILE:-}" ] && [ -n "${SW_SYSTEM_ID:-}" ] && upload+=(--system-id "$SW_SYSTEM_ID")
  sw "${upload[@]}"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "path=$path"
    echo "packages=$packages"
  } >> "$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "Security Watch SBOM: \`$path\` with $packages packages." >> "$GITHUB_STEP_SUMMARY"
fi
