package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"hyperion/internal/xdp"
	"hyperion/pkg/maps"
	"hyperion/pkg/model"
)

func main() {
	if len(os.Args) < 3 {
		printUsage()
		return
	}

	command := os.Args[1]
	target := os.Args[2]

	switch command {
	case "load":
		loadXDP(target)
	case "add":
		manageFlow(target, true)
	case "delete":
		manageFlow(target, false)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage: flowctl <command> <target>")
	fmt.Println("Commands:")
	fmt.Println("  load <interface>      Attach XDP program to interface")
	fmt.Println("  add <ip:port>         Add flow to blocklist")
	fmt.Println("  delete <ip:port>      Remove flow from blocklist")
}

func loadXDP(ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Lookup network iface: %v", err)
	}

	var objs xdp.BpfObjects
	if err := xdp.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	mapPath := "/sys/fs/bpf/hyperion_blocked_flows"
	if err := objs.BlockedFlows.Pin(mapPath); err != nil {
		log.Fatalf("Pinning map: %v", err)
	}
	defer os.Remove(mapPath)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpEnforce,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("XDP attached to %s. Press Ctrl+C to exit.\n", ifaceName)
	select {}
}

func manageFlow(ipPort string, isAdd bool) {
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid format. Expected IP:PORT")
	}

	ipBytes := net.ParseIP(parts[0]).To4()
	if ipBytes == nil {
		log.Fatalf("Invalid IPv4 address")
	}

	portInt, err := strconv.Atoi(parts[1])
	if err != nil || portInt < 1 || portInt > 65535 {
		log.Fatalf("Invalid port number")
	}

	mapPath := "/sys/fs/bpf/hyperion_blocked_flows"
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map: %v", err)
	}
	defer m.Close()

	controller := maps.NewMapController(m)



	key := model.FlowKey{
		DstIp:   parts[0],
		DstPort: uint16(portInt),
	}

	if isAdd {
		expiresNs := uint64(time.Now().UnixNano()) + uint64(time.Hour.Nanoseconds())
		if err := controller.AddFlow(key, model.BlockEntry{ExpiresNs: expiresNs, RiskScore: 1.0}); err != nil {
			log.Fatalf("Failed to add flow: %v", err)
		}
		fmt.Printf("Added %s to blocked flows.\n", ipPort)
	} else {
		if err := controller.Delete(key); err != nil {
			log.Fatalf("Failed to delete flow: %v", err)
		}
		fmt.Printf("Deleted %s from blocked flows.\n", ipPort)
	}
}
