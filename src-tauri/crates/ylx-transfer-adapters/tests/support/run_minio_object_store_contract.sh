#!/usr/bin/env bash
# Hermetic C94 object-store lane.
#
# This script owns the short-lived MinIO service only. The Rust harness owns
# the random bucket/prefix and removes every object/multipart handle it creates
# before this script removes the container. It is deliberately a script rather
# than a workflow fragment so local runs and CI use the same service contract.
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
manifest="${repo_root}/src-tauri/Cargo.toml"
image="${YLX_MINIO_IMAGE:-}"
build_dir=""
owned_image=""
tmpfs_size="${YLX_MINIO_TMPFS_SIZE:-2g}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'C94 MinIO lane requires %s in PATH\n' "$1" >&2
    exit 2
  }
}

require_command docker
require_command curl
require_command python3
require_command sha256sum

docker info >/dev/null 2>&1 || {
  printf 'C94 MinIO lane requires a reachable Docker daemon\n' >&2
  exit 2
}

random_hex() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

nonce="$(random_hex)"
port="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
container="ylx-minio-contract-$$-${nonce:0:12}"
access_key="${YLX_MINIO_ACCESS_KEY:-ylx${nonce:0:20}}"
secret_key="${YLX_MINIO_SECRET_KEY:-ylx-contract-${nonce}${nonce:0:8}}"
endpoint="http://127.0.0.1:${port}"

cleanup() {
  status=$?
  if ((status != 0)); then
    docker logs "$container" >&2 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [[ -n "$owned_image" ]]; then
    docker image rm "$owned_image" >/dev/null 2>&1 || true
  fi
  if [[ -n "$build_dir" ]]; then
    rm -rf -- "$build_dir"
  fi
  exit "$status"
}
trap cleanup EXIT

# The upstream container registries no longer serve this release. Build the
# same MinIO version from its official, checksum-pinned GitHub release binary;
# scratch keeps the contract independent of another mutable base image.
if [[ -z "$image" ]]; then
  case "$(docker info --format '{{.Architecture}}')" in
    x86_64|amd64)
      arch="amd64"
      binary_sha="7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f"
      ;;
    aarch64|arm64)
      arch="arm64"
      binary_sha="5c83cd2cf151717ba0243f73e1c7802ff36e272b67144bdd7f1f7d684fd6f03d"
      ;;
    *) printf 'Unsupported Docker architecture for the pinned MinIO binary\n' >&2; exit 2 ;;
  esac
  release="RELEASE.2025-09-07T16-13-09Z"
  build_dir="$(mktemp -d)"
  curl --fail --location --silent --show-error --retry 3 \
    --connect-timeout 20 --max-time 300 \
    "https://github.com/minio/minio/releases/download/${release}/minio.linux-${arch}.${release}" \
    --output "${build_dir}/minio"
  printf '%s  %s\n' "$binary_sha" "${build_dir}/minio" | sha256sum --check --strict
  chmod 0755 "${build_dir}/minio"
  printf 'FROM scratch\nCOPY minio /minio\nENTRYPOINT ["/minio"]\n' > "${build_dir}/Dockerfile"
  image="ylx-minio-contract:${nonce}"
  owned_image="$image"
  docker build --network=none --tag "$image" "$build_dir" >/dev/null
fi

docker run --detach --rm \
  --name "$container" \
  --publish "127.0.0.1:${port}:9000" \
  --tmpfs "/data:rw,size=${tmpfs_size},mode=0700" \
  --env "MINIO_ROOT_USER=${access_key}" \
  --env "MINIO_ROOT_PASSWORD=${secret_key}" \
  "$image" server /data --address ':9000' --console-address ':9001' \
  >/dev/null

ready=0
for _ in $(seq 1 120); do
  if curl --fail --silent --show-error --max-time 2 "${endpoint}/minio/health/ready" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done
if ((ready == 0)); then
  printf 'MinIO did not become ready at %s\n' "$endpoint" >&2
  exit 1
fi

# Leaving bucket/prefix unset asks the Rust harness to generate isolated,
# lowercase names and to delete the owned bucket after the last key is gone.
export YLX_MINIO_ENDPOINT="$endpoint"
export YLX_MINIO_ACCESS_KEY="$access_key"
export YLX_MINIO_SECRET_KEY="$secret_key"
export YLX_MINIO_URL_STYLE="path"
export YLX_MINIO_REGION="us-east-1"
export YLX_MINIO_FAULT_PROXY="1"
export YLX_MINIO_REQUEST_TIMEOUT_SECS="30"
unset YLX_MINIO_BUCKET YLX_MINIO_PREFIX || true

printf 'C94 MinIO lane: image=%s endpoint=%s data_tmpfs=%s random_bucket=true random_prefix=true random_credentials=true fault_proxy=true\n' \
  "$image" "$endpoint" "$tmpfs_size"

cargo test \
  --manifest-path "$manifest" \
  --locked \
  -p ylx-transfer-adapters \
  --test object_store_contract \
  -- \
  --ignored \
  --nocapture \
  --test-threads=1
