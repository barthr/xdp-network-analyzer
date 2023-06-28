package ui

import (
	"fmt"
	"log"
	"xdp-network-analyzer/bpfutil"
	"xdp-network-analyzer/process"

	tea "github.com/charmbracelet/bubbletea"
)

type SelectMonitorPidMsg struct {
	ActivePid int
}

type PidMonitorModel struct {
	pid     int
	process *process.UnixProcess
}

func (p *PidMonitorModel) Init() tea.Cmd {
	var err error
	p.process, err = process.FindByPid(p.pid)
	if err != nil {
		log.Fatalf("Expected process with pid %d to be present: %s", p.pid, err)
	}
	// if err := repository.Pid.Save(p.pid); err != nil {
	// 	log.Fatalf("Failed saving pid %d to monitor dns: %s", p.pid, err)
	// }
	probe := bpfutil.Uprobe{
		Executable: "/lib64/libc.so.6",
		Symbol:     "getaddrinfo",
	}
	if err := probe.LoadProgram(bpfutil.DnsModule, "inspect_dns_lookup"); err != nil {
		log.Fatalf("Failed loading program from module for pid %d to monitor dns: %s", p.pid, err)
	}
	if err := probe.Attach(bpfutil.PROBE_TYPE_ENTRY, p.pid); err != nil {
		log.Fatalf("Failed attaching probe for pid %d to monitor dns: %s", p.pid, err)
	}

	// returnProbe := probe.Clone()
	// if err := returnProbe.LoadProgram(bpfutil.DnsModule, "inspect_dns_response"); err != nil {
	// 	log.Fatalf("Failed loading program from module for pid %d to monitor dns: %s", p.pid, err)
	// }
	// if err := returnProbe.Attach(bpfutil.PROBE_TYPE_RETURN, p.pid); err != nil {
	// 	log.Fatalf("Failed attaching probe for pid %d to monitor dns: %s", p.pid, err)
	// }

	return nil
}

func (p *PidMonitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return p, p.Init()
}

func (p *PidMonitorModel) View() string {
	return fmt.Sprintf("hello %d", p.pid)
}
