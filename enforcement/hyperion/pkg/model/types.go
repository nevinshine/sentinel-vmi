package model

// FlowKey uniquely identifies a network flow that should be blocked.
type FlowKey struct {
	DstIp   string
	DstPort uint16
}

// BlockEntry represents the metadata attached to a blocked flow.
type BlockEntry struct {
	ExpiresNs uint64
	RiskScore float64
}

// NetworkTarget represents a specific destination for a decision event.
type NetworkTarget struct {
	DstIp    string  `json:"dst_ip"`
	DstPort  uint16  `json:"dst_port"`
	FlowRisk float64 `json:"flow_risk"`
}

// DecisionEvent represents the JSON payload emitted by the decision bus.
type DecisionEvent struct {
	EventID        string          `json:"event_id"`
	Action         string          `json:"action"`
	TTLSeconds     int             `json:"ttl_seconds"`
	NetworkTargets []NetworkTarget `json:"network_targets"`
	RiskScore      float64         `json:"risk_score"`
}
