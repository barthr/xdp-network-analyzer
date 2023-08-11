package bpfutil

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	// currently we have these as "global" variables since they are used throughout the program
	DnsModule *bpf.Module
)

func LoadModuleFromFile(path string) (*bpf.Module, error) {
	var err error
	ActiveModule, err := bpf.NewModuleFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	err = ActiveModule.BPFLoadObject()
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	return ActiveModule, nil
}

func LoadDnsLookupModule(path string) error {
	var err error
	DnsModule, err = LoadModuleFromFile(path)
	return err
}
