package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type request_event Bpf discovery.c -- -I../headers -O2 -g
