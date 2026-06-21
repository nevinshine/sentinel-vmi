package bus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"hyperion/pkg/model"
)

// TailFile reads the JSONL decision bus and sends events to a channel
func TailFile(path string, out chan<- model.DecisionEvent) {
	for {
		file, err := os.Open(path)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		// Seek to end
		file.Seek(0, 2)
		reader := bufio.NewReader(file)

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			var ev model.DecisionEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				fmt.Printf("JSON error: %v\n", err)
				continue
			}

			if ev.Action == "deny" {
				out <- ev
			}
		}
	}
}
