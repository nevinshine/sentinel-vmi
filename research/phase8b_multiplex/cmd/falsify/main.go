package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"phase8b_multiplex/internal/bpf"
)

var (
	numRequests = flag.Int("requests", 10, "Total number of concurrent requests")
	numSockets  = flag.Int("sockets", 5, "Max sockets (MaxConnsPerHost)")
)

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach cgroup/connect4
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

	// Attach TC egress
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get interfaces: %v", err)
	}
	var defaultIface net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			defaultIface = iface
			break
		}
	}
	tcxL, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: defaultIface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("Failed to attach tc/egress: %v", err)
	}
	defer tcxL.Close()

	// Initialize the PID/TGID in maps for the loader process
	// All our goroutines share this PID.
	// Phase 8A assumes 1 Process = 1 Behavior. 
	// We will purposefully tag the entire process with BehaviorID 0x41.
	pid := uint64(os.Getpid())
	computedBehaviorID := uint64(0x41) 
	
	pctx := bpf.BpfProcessContext{SubjectHash: 0xDEADBEEF, LineageHash: 0xCAFEBABE}
	objs.ProcessMap.Put(&pid, &pctx)
	bctx := bpf.BpfBehaviorContext{BehaviorId: computedBehaviorID, PidTgid: pid}
	objs.BehaviorMap.Put(&pid, &bctx)

	log.Println("[*] Phase 8B Multiplexed Falsification Engine")
	log.Printf("[*] Mode: %d Requests over %d Max Sockets", *numRequests, *numSockets)
	log.Printf("[*] Process Tagged with Computed_BehaviorID: 0x%X", computedBehaviorID)

	// Set up Perf Reader
	rd, err := perf.NewReader(objs.ValidationEvents, os.Getpagesize()*4)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	var mu sync.Mutex
	totalEvents := 0
	falseAttributions := 0
	firstRequestFalse := 0
	reusedSocketFalse := 0

	go func() {
		var event bpf.BpfValidationEvent
		for {
			record, err := rd.Read()
			if err != nil {
				// if perf.IsClosed(err) ...
				// wait we can just check string or just break
				if err.Error() == "perf ring buffer closed" || err.Error() == "file already closed" {
					return
				}
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			mu.Lock()
			totalEvents++
			
			// Falsification check: did the socket's connect() tag match the true L7 tag?
			isMatch := event.ComputedBehaviorId == event.TrueBehaviorId
			
			if !isMatch {
				falseAttributions++
				if event.SocketReuseCount == 0 {
					firstRequestFalse++
				} else {
					reusedSocketFalse++
				}
			}

			// Debug print for visibility
			// log.Printf("[Event] Socket: %d | ReuseCount: %d | Computed: %X | True: %X | Match: %t", 
			// 	event.SocketCookie, event.SocketReuseCount, event.ComputedBehaviorId, event.TrueBehaviorId, isMatch)

			mu.Unlock()
		}
	}()

	// Wait 1s for BPF to settle
	time.Sleep(1 * time.Second)

	// Configure connection pooling
	transport := &http.Transport{
		MaxConnsPerHost:     *numSockets,
		MaxIdleConnsPerHost: *numSockets,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{Transport: transport}

	// Blast requests
	var wg sync.WaitGroup
	for i := 1; i <= *numRequests; i++ {
		wg.Add(1)
		go func(reqID int) {
			defer wg.Done()
			
			// Generate True Behavior ID for this specific request
			trueBehaviorID := uint64(0x1000 + reqID)
			
			req, err := http.NewRequest("GET", "http://1.1.1.1:80", nil)
			if err == nil {
				// We MUST inject exactly 8 hex chars. 
				hexID := fmt.Sprintf("%08x", trueBehaviorID)
				req.Header.Add("X-Bid", hexID)
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}(i)
	}

	wg.Wait()
	
	// Wait for perf events to flush
	time.Sleep(2 * time.Second)
	rd.Close()

	mu.Lock()
	defer mu.Unlock()

	accuracy := 100.0
	falseRate := 0.0
	if totalEvents > 0 {
		falseRate = float64(falseAttributions) / float64(totalEvents) * 100.0
		accuracy = 100.0 - falseRate
	}

	reuseRatio := float64(*numRequests) / float64(*numSockets)

	fmt.Printf("\n=== Phase 8B Falsification Matrix Row ===\n")
	fmt.Printf("| Requests | Sockets | Reuse Ratio | Accuracy | False Rate |\n")
	fmt.Printf("| -------- | ------- | ----------- | -------- | ---------- |\n")
	fmt.Printf("| %-8d | %-7d | %-11.1f | %-7.1f%% | %-9.1f%% |\n\n", 
		*numRequests, *numSockets, reuseRatio, accuracy, falseRate)

	fmt.Printf("=== Failure Localization ===\n")
	fmt.Printf("| Scenario                 | False Attributions |\n")
	fmt.Printf("| ------------------------ | ------------------ |\n")
	fmt.Printf("| First Request on Socket  | %-18d |\n", firstRequestFalse)
	fmt.Printf("| Reused Socket            | %-18d |\n\n", reusedSocketFalse)
}
