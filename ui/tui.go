package ui

import (
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	p *tea.Program
)

type view int

const (
	processOverview view = iota
	pidMonitor
)

type Model struct {
	currentView view

	processView    tea.Model
	pidMonitorView tea.Model

	activePid int
}

func StartTea() {
	if os.Getenv("DEBUG") != "" {
		if f, err := tea.LogToFile("debug.log", "debug"); err != nil {
			fmt.Printf("Couldn't open file for logging: %s\n", err)
			os.Exit(1)
		} else {
			defer func() {
				err = f.Close()
				if err != nil {
					log.Fatal(err)
				}
			}()
		}
	}
	p = tea.NewProgram(Model{
		processView: PidTable(),
	})
	_, err := p.Run()
	if err != nil {
		fmt.Printf("Something unexpected happened: %s\n", err)
		os.Exit(1)
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) View() string {
	switch m.currentView {
	case processOverview:
		return m.processView.View()
	case pidMonitor:
		return m.pidMonitorView.View()
	default:
		fmt.Printf("There should always be a view for a route: %d\n", m.currentView)
		os.Exit(1)
		return ""
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case selectPidMessage:
		m.activePid = msg.pid
		m.currentView = pidMonitor
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEscape:
			if m.currentView != processOverview {
				m.activePid = 0
				m.currentView = processOverview
			}
		}
	}

	switch m.currentView {
	case processOverview:
		m.processView, cmd = m.processView.Update(msg)
		cmds = append(cmds, cmd)
	case pidMonitor:
		model := &PidMonitorModel{pid: m.activePid}
		model.Init()
		m.pidMonitorView, cmd = model.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}
