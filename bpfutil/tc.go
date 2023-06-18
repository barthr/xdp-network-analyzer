package bpfutil

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"syscall"
)

type Tc struct {
	InterfaceName string

	bpfProgram *bpf.BPFProg
	hook       *bpf.TcHook
}

func (tc *Tc) LoadProgram(module *bpf.Module, progName string) error {
	var err error
	tc.bpfProgram, err = module.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("failed loading bpf program %s: %w", progName, err)
	}
	tc.hook = module.TcHookInit()
	return nil
}

func (tc *Tc) Attach(attachPoint bpf.TcAttachPoint) error {
	err := tc.hook.SetInterfaceByName(tc.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to set tc hook on interface %s: %w", tc.InterfaceName, err)
	}

	tc.hook.SetAttachPoint(attachPoint)
	err = tc.hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			return fmt.Errorf("failed to create tc hook on interface %s: %w", tc.InterfaceName, err)
		}
	}

	tcOpts := bpf.TcOpts{ProgFd: tc.bpfProgram.FileDescriptor()}
	err = tc.hook.Attach(&tcOpts)
	if err != nil {
		return fmt.Errorf("failed attaching hook on interface %s: %w", tc.InterfaceName, err)
	}
	return nil
}
