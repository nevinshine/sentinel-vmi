#!/usr/bin/env bash
set -euo pipefail

endpoint="${VMI_GRPC_ENDPOINT:-localhost:8421}"
method="${VMI_GRPC_METHOD:-}"
plaintext="${VMI_GRPC_PLAINTEXT:-1}"

if ! command -v grpcurl >/dev/null 2>&1; then
  echo "[vmi-grpc-forwarder] ERROR: grpcurl not found in PATH" >&2
  exit 1
fi

if [[ -z "$method" ]]; then
  echo "[vmi-grpc-forwarder] ERROR: VMI_GRPC_METHOD is required (for example: telos.vmi.AlertService/PushAlert)" >&2
  exit 1
fi

grpc_args=()
if [[ "$plaintext" == "1" || "$plaintext" == "true" || "$plaintext" == "yes" ]]; then
  grpc_args+=("-plaintext")
fi

while IFS= read -r line; do
  [[ -z "$line" ]] && continue

  if ! grpcurl "${grpc_args[@]}" -d "$line" "$endpoint" "$method" >/dev/null 2>&1; then
    echo "[vmi-grpc-forwarder] WARN: failed to deliver payload" >&2
  fi
done
