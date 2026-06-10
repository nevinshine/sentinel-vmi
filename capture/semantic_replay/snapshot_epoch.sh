#!/bin/bash
# capture/semantic_replay/snapshot_epoch.sh
# Dumps epoch-aligned Kubernetes and Cilium state to correlate with semantic captures.

set -e

EPOCH_ID=$1
if [ -z "$EPOCH_ID" ]; then
    echo "Usage: $0 <epoch_id>"
    exit 1
fi

VAGRANT_DIR="$(pwd)/deploy/vagrant"

function run_on_cp() {
    cd "$VAGRANT_DIR" && vagrant ssh control-plane -c "sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml $1" 2>/dev/null
}

if [ "$EPOCH_ID" == "verify" ]; then
    echo "Verifying cluster state..."
    run_on_cp "kubectl get nodes -o wide"
    run_on_cp "kubectl get pods -A"
    run_on_cp "cilium status"
    exit 0
fi

OUT_DIR="$(pwd)/capture/semantic_replay/epoch_${EPOCH_ID}"
mkdir -p "$OUT_DIR"

echo "Snapshotting Cluster State for Epoch ${EPOCH_ID}..."

run_on_cp "kubectl get nodes -o yaml" > "${OUT_DIR}/nodes.yaml" || echo "No nodes found"
run_on_cp "kubectl get namespaces -o yaml" > "${OUT_DIR}/namespaces.yaml" || echo "No namespaces found"
run_on_cp "kubectl get deployments --all-namespaces -o yaml" > "${OUT_DIR}/deployments.yaml" || echo "No deployments found"
run_on_cp "kubectl get pods --all-namespaces -o wide" > "${OUT_DIR}/pods_wide.txt" || echo "No pods found"

# Cilium specific snapshots
run_on_cp "cilium bpf policy get --all" > "${OUT_DIR}/cilium_bpf_policy.txt" || echo "Cilium CLI not found or policy extraction failed"

echo "Epoch ${EPOCH_ID} snapshot complete."
