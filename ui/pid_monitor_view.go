package ui

import (
	"fmt"
	"log"
	"xdp-network-analyzer/process"
	"xdp-network-analyzer/repository"

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
	if err := repository.Pid.Save(p.pid); err != nil {
		log.Fatalf("Failed saving pid %d to monitor dns: %s", p.pid, err)
	}
	return nil
}

func (p *PidMonitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return p, p.Init()
}

func (p *PidMonitorModel) View() string {
	return fmt.Sprintf("hello %d", p.pid)
}
