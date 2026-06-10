#!/bin/bash
# capture/semantic_replay/snapshot_epoch.sh
# Dumps epoch-aligned Kubernetes and Cilium state to correlate with semantic captures.

set -e

EPOCH_ID=$1
if [ -z "$EPOCH_ID" ]; then
    echo "Usage: $0 <epoch_id>"
    exit 1
fi

OUT_DIR="capture/semantic_replay/epoch_${EPOCH_ID}"
mkdir -p "$OUT_DIR"

echo "Snapshotting Cluster State for Epoch ${EPOCH_ID}..."

kubectl get nodes -o yaml > "${OUT_DIR}/nodes.yaml" 2>/dev/null || echo "No nodes found"
kubectl get namespaces -o yaml > "${OUT_DIR}/namespaces.yaml" 2>/dev/null || echo "No namespaces found"
kubectl get deployments --all-namespaces -o yaml > "${OUT_DIR}/deployments.yaml" 2>/dev/null || echo "No deployments found"
kubectl get pods --all-namespaces -o wide > "${OUT_DIR}/pods_wide.txt" 2>/dev/null || echo "No pods found"

# Cilium specific snapshots (assuming cilium CLI is installed)
cilium bpf policy get --all > "${OUT_DIR}/cilium_bpf_policy.txt" 2>/dev/null || echo "Cilium CLI not found or policy extraction failed"

echo "Epoch ${EPOCH_ID} snapshot complete."
