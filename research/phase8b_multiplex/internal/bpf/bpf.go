package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type process_context -type behavior_context -type behavior_tag Bpf falsify.c -- -I../headers -O2 -g
