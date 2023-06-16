package bpfutil

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
)

func LoadModuleFromFile(path string) (*bpf.Module, error) {
	module, err := bpf.NewModuleFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	err = module.BPFLoadObject()
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	return module, nil
}
