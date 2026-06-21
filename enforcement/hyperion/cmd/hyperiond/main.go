package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"

	"hyperion/pkg/bus"
	"hyperion/pkg/maps"
	"hyperion/pkg/model"
	"hyperion/pkg/ttl"
)

func main() {
	fmt.Println("[*] Starting Hyperion XDP Enforcement Daemon (hyperiond)")

	mapPath := "/sys/fs/bpf/hyperion_blocked_flows"
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map (is XDP attached?): %v", err)
	}
	defer m.Close()

	controller := maps.NewMapController(m)

	// Phase 7A.2: Startup Reconciliation
	ttl.ReconcileExpiredEntries(controller)

	// Start garbage collector
	go ttl.SweepExpiredEntries(controller)

	busPath := "decision_bus.jsonl"
	fmt.Printf("[*] Tailing Decision Bus: %s\n", busPath)

	events := make(chan model.DecisionEvent)
	go bus.TailFile(busPath, events)

	for ev := range events {
		for _, target := range ev.NetworkTargets {
			now := time.Now()
			expiresNs := uint64(now.UnixNano()) + uint64(ev.TTLSeconds)*uint64(time.Second.Nanoseconds())

			err := controller.AddFlow(
				model.FlowKey{DstIp: target.DstIp, DstPort: target.DstPort},
				model.BlockEntry{ExpiresNs: expiresNs, RiskScore: ev.RiskScore},
			)
			if err != nil {
				fmt.Printf("[!] Failed to add flow %s:%d: %v\n", target.DstIp, target.DstPort, err)
			} else {
				fmt.Printf("[+] XDP_DROP Enforcement active: %s:%d (Risk: %.2f, Expires: %ds)\n", 
					target.DstIp, target.DstPort, ev.RiskScore, ev.TTLSeconds)
			}
		}
	}
}
