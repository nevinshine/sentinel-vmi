package ttl

import (
	"fmt"
	"time"

	"hyperion/internal/xdp"
	"hyperion/pkg/maps"
)

// ReconcileExpiredEntries sweeps the map once synchronously, designed for startup recovery.
func ReconcileExpiredEntries(c *maps.MapController) {
	nowNs := uint64(time.Now().UnixNano())
	swept := 0

	var key xdp.BpfFlowKey
	var val xdp.BpfBlockEntry
	iterator := c.Iterate()
	
	var toDelete []xdp.BpfFlowKey
	for iterator.Next(&key, &val) {
		if nowNs > val.ExpiresNs {
			toDelete = append(toDelete, key)
		}
	}

	for _, k := range toDelete {
		c.DeleteBpf(k)
		swept++
	}

	if swept > 0 {
		fmt.Printf("[Reconcile] Swept %d expired flows on startup\n", swept)
	}
}

// SweepExpiredEntries periodically removes expired entries from the BPF map
func SweepExpiredEntries(c *maps.MapController) {
	for {
		nowNs := uint64(time.Now().UnixNano())

		var key xdp.BpfFlowKey
		var val xdp.BpfBlockEntry
		iterator := c.Iterate()
		
		var toDelete []xdp.BpfFlowKey
		for iterator.Next(&key, &val) {
			if nowNs > val.ExpiresNs {
				toDelete = append(toDelete, key)
			}
		}

		for _, k := range toDelete {
			c.DeleteBpf(k)
			fmt.Printf("[Sweep] Deleted expired flow key: IP=%d Port=%d\n", k.DstIp, k.DstPort)
		}

		time.Sleep(10 * time.Second)
	}
}
