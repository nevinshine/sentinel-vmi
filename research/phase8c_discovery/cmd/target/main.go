package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	
	"phase8c_discovery/internal/bpf"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Open current executable
	ex, err := link.OpenExecutable(os.Args[0])
	if err != nil {
		log.Fatalf("Failed to open executable: %v", err)
	}

	// Attach uprobe to RoundTrip
	up, err := ex.Uprobe("net/http.(*Transport).RoundTrip", objs.UprobeRoundtrip, nil)
	if err != nil {
		log.Fatalf("Failed to attach uprobe: %v", err)
	}
	defer up.Close()

	// Start Perf Reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	eventChan := make(chan bpf.BpfRequestEvent, 100)
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err.Error() == "perf ring buffer closed" {
					return
				}
				continue
			}

			var event bpf.BpfRequestEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			eventChan <- event
		}
	}()

	time.Sleep(1 * time.Second) // wait for uprobe to settle

	log.Println("[*] Phase 8C Experiment 1: Request Observability")
	log.Println("[*] Emitting 10 requests...")

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	expectedRequests := 10
	for i := 0; i < expectedRequests; i++ {
		req, err := http.NewRequestWithContext(context.Background(), "GET", "http://1.1.1.1:80", nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}
		
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Request failed (expected if 1.1.1.1 ignores us, but RoundTrip still runs): %v", err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	log.Println("[*] Done sending requests. Collecting events...")
	time.Sleep(1 * time.Second) // allow perf events to flush

	received := 0
	for {
		select {
		case ev := <-eventChan:
			method := cstring(ev.Method[:])
			host := cstring(ev.Host[:])
			log.Printf("=> [Uprobe] req_ptr: 0x%x | ctx_ptr: 0x%x | %s %s", ev.RequestPtr, ev.ContextPtr, method, host)
			received++
		default:
			log.Printf("[*] Result: Sent %d, Recovered %d", expectedRequests, received)
			if received == expectedRequests {
				log.Println("[SUCCESS] 100% extraction rate")
			} else {
				log.Println("[FAIL] Extraction rate mismatch")
			}
			return
		}
	}
}

func cstring(b []int8) string {
	var buf []byte
	for _, v := range b {
		if v == 0 {
			break
		}
		buf = append(buf, byte(v))
	}
	return string(buf)
}
