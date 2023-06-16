package bpfutil

import (
	"errors"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

type ProbeType int

const (
	PROBE_TYPE_ENTRY ProbeType = iota
	PROBE_TYPE_RETURN
)

type Uprobe struct {
	Executable string
	Symbol     string

	bpfProgam *bpf.BPFProg
	probe     *bpf.BPFLink
}

func (p *Uprobe) LoadProgram(module *bpf.Module, progName string) error {
	var err error
	p.bpfProgam, err = module.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("failed loading bpf program %s: %w", progName, err)
	}
	return nil
}

func (p *Uprobe) Attach(probeType ProbeType, pid ...int) error {
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
	case PROBE_TYPE_ENTRY:
		p.probe, err = p.bpfProgam.AttachUprobe(probePid, p.Executable, offset)
	case PROBE_TYPE_RETURN:
		p.probe, err = p.bpfProgam.AttachURetprobe(probePid, p.Executable, offset)
	default:
		return errors.New("trying to attach unknown probe type supported are: PROBE_TYPE_ENTRY or PROBE_TYPE_RETURN")
	}
	if err != nil {
		return fmt.Errorf("failed attachin probe %s on executable %s %w", p.Symbol, p.Executable, err)
	}
	return nil

}

func (p *Uprobe) Detach() error {
	return p.probe.Destroy()
}
