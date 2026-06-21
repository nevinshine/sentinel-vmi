package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"encoding/binary"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"phase8_attribution/internal/bpf"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	log.Println("[*] Starting Phase 8A Attribution Loader")

	// Load pre-compiled programs and maps into the kernel.
	objs := bpf.bpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach kprobe to tcp_connect
	kp, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
	if err != nil {
		log.Fatalf("Failed to attach tcp_connect kprobe: %v", err)
	}
	defer kp.Close()
	log.Println("[+] Attached kprobe/tcp_connect")

	// Attach cgroup_skb/egress hook
	// For Experiment 1, we will attach to the root cgroup v2.
	cgroupPath := "/sys/fs/cgroup"
	cgroupL, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  objs.EgressPacketCapture.Type(),
		Program: objs.EgressPacketCapture,
	})
	if err != nil {
		log.Fatalf("Failed to attach cgroup_skb: %v", err)
	}
	defer cgroupL.Close()
	log.Println("[+] Attached cgroup_skb/egress to", cgroupPath)

	// Set up Experiment 1 Fake Behavior
	pid := uint64(os.Getpid())
	behaviorID := uint64(0x41) // "A"

	// 1. Populate process_map
	pctx := bpf.BpfProcessContext{
		SubjectHash: 0xDEADBEEF,
		LineageHash: 0xCAFEBABE,
	}
	if err := objs.ProcessMap.Put(&pid, &pctx); err != nil {
		log.Fatalf("Failed to put process_map: %v", err)
	}

	// 2. Populate behavior_map
	bctx := bpf.BpfBehaviorContext{
		BehaviorId: behaviorID,
		PidTgid:    pid,
	}
	if err := objs.BehaviorMap.Put(&pid, &bctx); err != nil {
		log.Fatalf("Failed to put behavior_map: %v", err)
	}

	log.Printf("[*] Experiment 1 Environment Ready")
	log.Printf("    PID: %d", pid)
	log.Printf("    BehaviorID: 0x%X", behaviorID)
	log.Println("[*] Waiting for test traffic... Press Ctrl+C to exit")

	// In the background, let's trigger a connect() ourselves or wait for curl!
	go func() {
		time.Sleep(2 * time.Second)
		log.Println("[*] Self-test: connecting to 1.1.1.1:80")
		conn, err := net.Dial("tcp", "1.1.1.1:80")
		if err != nil {
			log.Printf("[!] Dial failed: %v", err)
		} else {
			log.Printf("[+] Dial success: Local=%s Remote=%s", conn.LocalAddr(), conn.RemoteAddr())
			conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			conn.Close()
		}
	}()

	// Watch the flow_map for entries
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			var key bpf.BpfFlowKey
			var val bpf.BpfFlowAttribution
			entries := objs.FlowMap.Iterate()
			for entries.Next(&key, &val) {
				srcIp := intToIP(key.SrcIp)
				dstIp := intToIP(key.DstIp)
				log.Printf("    Flow: %s:%d -> %s:%d/TCP", srcIp, key.SrcPort, dstIp, key.DstPort)
				log.Printf("    Recovered BehaviorID: 0x%X (Packets: %d)", val.BehaviorId, val.PacketCount)
				
				// Delete to only print once
				objs.FlowMap.Delete(&key)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("[*] Exiting")
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}
