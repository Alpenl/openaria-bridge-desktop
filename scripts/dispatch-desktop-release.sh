#!/usr/bin/env bash
set -euo pipefail

repository="Alpenl/openaria-bridge-desktop"
workflow="ci.yml"
api_version="2026-03-10"

usage() {
  echo "Usage: $0 <40-character-source-commit> <X.Y.Z> [--allow-legacy-baseline-bootstrap]" >&2
  exit 2
}

[[ "$#" -eq 2 || "$#" -eq 3 ]] || usage
source_commit="$1"
release_tag="$2"
allow_legacy_baseline_bootstrap=false
if [[ "$#" -eq 3 ]]; then
  [[ "$3" == "--allow-legacy-baseline-bootstrap" ]] || usage
  allow_legacy_baseline_bootstrap=true
fi
if [[ ! "${source_commit}" =~ ^[0-9a-f]{40}$ ]] ||
  [[ ! "${release_tag}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  usage
fi
if [[ "${release_tag}" == "0.1.6" && "${allow_legacy_baseline_bootstrap}" != "true" ]]; then
  echo "Release 0.1.6 requires --allow-legacy-baseline-bootstrap." >&2
  exit 1
fi
if [[ "${release_tag}" != "0.1.6" && "${allow_legacy_baseline_bootstrap}" == "true" ]]; then
  echo "Legacy baseline bootstrap is authorized only for 0.1.6." >&2
  exit 1
fi

for tool in gh jq sha256sum date; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Missing required release operator tool: ${tool}" >&2
    exit 1
  fi
done

repository_owner="${repository%%/*}"
actor="$(gh api user --jq .login)"
if [[ "${actor}" != "${repository_owner}" ]]; then
  echo "The authenticated GitHub actor must be repository owner ${repository_owner}; got ${actor}." >&2
  exit 1
fi

repository_metadata="$(gh api "repos/${repository}")"
if ! jq -e '
  (type == "object") and
  (.default_branch | type) == "string" and
  (.default_branch | length) > 0 and
  .permissions.admin == true
' <<<"${repository_metadata}" >/dev/null; then
  echo "The repository-owner identity must have GitHub repository administration permission." >&2
  exit 1
fi
default_branch="$(jq -r .default_branch <<<"${repository_metadata}")"

remote_commit="$(gh api "repos/${repository}/commits/${source_commit}" --jq .sha)"
if [[ "${remote_commit}" != "${source_commit}" ]]; then
  echo "The exact source commit is not available in ${repository}." >&2
  exit 1
fi
default_branch_head="$(gh api "repos/${repository}/commits/${default_branch}" --jq .sha)"
if [[ "${default_branch_head}" != "${source_commit}" ]]; then
  echo "The release source must equal the current ${default_branch} head ${default_branch_head}; got ${source_commit}." >&2
  exit 1
fi

control_root="$(mktemp -d)"
cleanup() {
  rm -rf "${control_root}"
}
trap cleanup EXIT
raw_response_file="${control_root}/immutable-releases-response.json"

# Keep this as the final remote read before dispatch. It uses the operator's
# admin-capable local gh identity; the workflow token has no Administration scope.
gh api \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: ${api_version}" \
  "repos/${repository}/immutable-releases" \
  > "${raw_response_file}"
if ! jq -e '
  (type == "object") and
  (keys == ["enabled", "enforced_by_owner"]) and
  .enabled == true and
  (.enforced_by_owner | type) == "boolean"
' "${raw_response_file}" >/dev/null; then
  echo "GitHub immutable Releases are not enabled or the official response schema is unexpected." >&2
  exit 1
fi

checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
# Preserve the API payload's formatting; command substitution only removes the
# CLI-added trailing newline, while the workflow binds and hashes these bytes.
raw_response="$(<"${raw_response_file}")"
response_sha256="$(printf %s "${raw_response}" | sha256sum | cut -d ' ' -f 1)"

# Reruns are deliberately rejected. Every publication attempt requires a new
# owner/admin read and a new workflow_dispatch run against the current HEAD.
gh workflow run "${workflow}" \
  --repo "${repository}" \
  --ref "${default_branch}" \
  -f release_tag="${release_tag}" \
  -f source_commit="${source_commit}" \
  -f immutable_preflight_actor="${actor}" \
  -f immutable_preflight_checked_at="${checked_at}" \
  -f immutable_preflight_raw_response="${raw_response}" \
  -f immutable_preflight_sha256="${response_sha256}" \
  -f allow_legacy_baseline_bootstrap="${allow_legacy_baseline_bootstrap}"

echo "Dispatched ${workflow} for ${release_tag} at ${source_commit}."
