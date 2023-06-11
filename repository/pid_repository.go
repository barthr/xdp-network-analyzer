package repository

import (
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	Pid *PidRepository
	key = 1
)

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
	return p.pidMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&pid))
}

func (p *PidRepository) Clear(pid int) error {
	return p.pidMap.DeleteKey(unsafe.Pointer(&key))
}
