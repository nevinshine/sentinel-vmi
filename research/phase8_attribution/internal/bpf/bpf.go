package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb Bpf attribution.c -- -I/usr/include/bpf
