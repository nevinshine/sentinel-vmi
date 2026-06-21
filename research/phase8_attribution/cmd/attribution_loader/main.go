package main

import (
	"log"
	"net"
	"os/signal"
	"encoding/binary"
	"syscall"
	"time"
	"fmt"

	"os/exec"
	"flag"
	"sync"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"phase8_attribution/internal/bpf"
)

var worker = flag.Bool("worker", false, "Run as worker")
var numClients = flag.Int("clients", 1, "Number of concurrent clients to run")

func main() {
	flag.Parse()

	if *worker {
		// Print PID and wait for signal
		fmt.Printf("%d\n", os.Getpid())
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		
		conn, _ := net.Dial("tcp", "1.1.1.1:80")
		if conn != nil {
			conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			conn.Close()
		}
		return
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	log.Println("[*] Starting Phase 8A Attribution Loader")

	// Load pre-compiled programs and maps into the kernel.
	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach cgroup/connect4 hook
	// For Experiment 1, we will attach to the root cgroup v2.
	cgroupPath := "/sys/fs/cgroup"
	cgroupConn, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgroupConnect4,
	})
	if err != nil {
		log.Fatalf("Failed to attach cgroup/connect4: %v", err)
	}
	defer cgroupConn.Close()
	log.Println("[+] Attached cgroup/connect4 to", cgroupPath)

	// Attach tc/egress hook to the primary network interface
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get interfaces: %v", err)
	}
	var defaultIface net.Interface
	for _, iface := range ifaces {
		// Pick the first non-loopback up interface
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			defaultIface = iface
			break
		}
	}
	log.Printf("[*] Using interface %s (%d) for TC egress hook", defaultIface.Name, defaultIface.Index)
	
	tcxL, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: defaultIface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("Failed to attach tc/egress: %v", err)
	}
	defer tcxL.Close()
	log.Println("[+] Attached tc/egress to", defaultIface.Name)

	// End-to-End Metrics
	clients := *numClients
	if clients == 0 {
		clients = 1
	}
	
	log.Printf("[*] Launching %d concurrent clients...", clients)

	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-worker")
			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			
			cmd.Start()
			
			// Read PID from worker
			var workerPid uint64
			fmt.Fscanf(stdout, "%d\n", &workerPid)
			
			behaviorID := uint64(0x40 + clientID)
			
			// Populate maps
			pctx := bpf.BpfProcessContext{SubjectHash: 0xDEADBEEF, LineageHash: 0xCAFEBABE}
			objs.ProcessMap.Put(&workerPid, &pctx)
			
			bctx := bpf.BpfBehaviorContext{BehaviorId: behaviorID, PidTgid: workerPid}
			objs.BehaviorMap.Put(&workerPid, &bctx)
			
			// Signal worker to connect
			stdin.Write([]byte("\n"))
			cmd.Wait()
		}(i)
	}

	// Wait for all workers to complete
	wg.Wait()
	log.Println("[*] All clients completed. Waiting for BPF map sync...")
	time.Sleep(2 * time.Second)

	// Collect statistics
	recoveredCount := 0
	var key bpf.BpfFlowKey
	var val bpf.BpfFlowAttribution
	entries := objs.FlowMap.Iterate()
	for entries.Next(&key, &val) {
		recoveredCount++
		// Just to debug
		if clients <= 10 {
			srcIp := intToIP(key.SrcIp)
			dstIp := intToIP(key.DstIp)
			log.Printf("    Flow: %s:%d -> %s:%d/TCP", srcIp, key.SrcPort, dstIp, key.DstPort)
			log.Printf("    Recovered BehaviorID: 0x%X (Packets: %d)", val.BehaviorId, val.PacketCount)
		}
	}
	
	successRate := float64(recoveredCount) / float64(clients) * 100.0
	log.Printf("=== Phase 8A End-to-End Metrics ===")
	log.Printf("Clients Spawned  : %d", clients)
	log.Printf("Flows Recovered  : %d", recoveredCount)
	log.Printf("Success Rate     : %.2f%%", successRate)
	if recoveredCount < clients {
		log.Printf("Missing Rate     : %.2f%%", 100.0 - successRate)
	} else {
		log.Printf("Missing Rate     : 0.00%%")
	}

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
