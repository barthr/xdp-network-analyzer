package repository

import (
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

var Pid *PidRepository

type PidRepository struct {
	pidMap *bpf.BPFMap
}

func NewPidRepository(module *bpf.Module, name string) (*PidRepository, error) {
	pidMap, err := module.GetMap(name)
	if err != nil {
		return nil, err
	}
	return &PidRepository{pidMap}, nil
}

func (p *PidRepository) Save(pid int) error {
	if err := p.Clear(pid); err != nil {
		return err
	}
	return p.pidMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&pid))
}

func (p *PidRepository) Clear(pid int) error {
	return p.pidMap.DeleteKey(unsafe.Pointer(&pid))
}
