package uprobe

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

type ProbeType int

const (
	ENTRY ProbeType = iota
	RETURN
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
)

type Probe struct {
	Executable string
	Symbol     string

	bpfModule *bpf.Module
	bpfProgam *bpf.BPFProg
	probe     *bpf.BPFLink
}

func (p *Probe) LoadModule(path string, progName string) error {
	var err error
	p.bpfModule, err = bpf.NewModuleFromFile(path)
	if err != nil {
		return fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	err = p.bpfModule.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	p.bpfProgam, err = p.bpfModule.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("failed loading bpf program %s: %w", progName, err)
	}
	return nil
}

func (p *Probe) Attach(probeType ProbeType, pid ...int) error {
	offset, err := helpers.SymbolToOffset(p.Executable, p.Symbol)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	probePid := -1
	if len(pid) > 0 {
		probePid = pid[0]
	}

	switch probeType {
	case ENTRY:
		p.probe, err = p.bpfProgam.AttachUprobe(probePid, p.Executable, offset)
	case RETURN:
		p.probe, err = p.bpfProgam.AttachURetprobe(probePid, p.Executable, offset)
	default:
		return errors.New("trying to attach unknown probe type supported are: ENTRY or RETURN")
	}
	if err != nil {
		return fmt.Errorf("failed attachin probe %s on executable %s %w", p.Symbol, p.Executable, err)
	}
	return nil

}

func (p *Probe) Detach() error {
	return p.probe.Destroy()
}
