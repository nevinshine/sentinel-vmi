package maps

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"hyperion/internal/xdp"
	"hyperion/pkg/model"
)

// MapController abstracts the eBPF map operations
type MapController struct {
	m *ebpf.Map
}

func NewMapController(m *ebpf.Map) *MapController {
	return &MapController{m: m}
}

// AddFlow adds an IP:Port to the map
func (c *MapController) AddFlow(key model.FlowKey, entry model.BlockEntry) error {
	ipBytes := net.ParseIP(key.DstIp).To4()
	if ipBytes == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	ipLE := binary.LittleEndian.Uint32(ipBytes)
	
	portUint := make([]byte, 2)
	binary.BigEndian.PutUint16(portUint, key.DstPort)
	portLE := binary.LittleEndian.Uint16(portUint)

	bpfKey := xdp.BpfFlowKey{
		DstIp:   ipLE,
		DstPort: portLE,
	}

	bpfVal := xdp.BpfBlockEntry{
		ExpiresNs: entry.ExpiresNs,
		RiskScore: uint32(entry.RiskScore * 100),
	}

	return c.m.Put(bpfKey, bpfVal)
}

// Iterate exposes the underlying map iterator
func (c *MapController) Iterate() *ebpf.MapIterator {
	return c.m.Iterate()
}

// Delete removes a key
func (c *MapController) Delete(key model.FlowKey) error {
	ipBytes := net.ParseIP(key.DstIp).To4()
	if ipBytes == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	ipLE := binary.LittleEndian.Uint32(ipBytes)
	
	portUint := make([]byte, 2)
	binary.BigEndian.PutUint16(portUint, key.DstPort)
	portLE := binary.LittleEndian.Uint16(portUint)

	bpfKey := xdp.BpfFlowKey{
		DstIp:   ipLE,
		DstPort: portLE,
	}
	return c.m.Delete(bpfKey)
}

// DeleteBpf removes a key using the raw BPF key (useful for iterators)
func (c *MapController) DeleteBpf(key xdp.BpfFlowKey) error {
	return c.m.Delete(key)
}
