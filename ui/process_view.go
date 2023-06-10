package ui

import (
	"strconv"
	"xdp-network-analyzer/process"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"
)

type selectPidMessage struct {
	pid int
}

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type model struct {
	table table.Model
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEscape:
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case tea.KeyCtrlQ, tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
			return m, func() tea.Msg {
				v, _ := strconv.Atoi(m.table.SelectedRow()[0])
				return selectPidMessage{v}
			}
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return baseStyle.Render(m.table.View()) + "\n"
}

func PidTable() model {
	processes, err := process.Processes()
	if err != nil {
		// TODO: panic
		panic(err)
	}

	longestPid := lo.Max(lo.Map(processes, func(item *process.UnixProcess, index int) int {
		return len(strconv.Itoa(item.Pid()))
	}))

	longestParent := lo.Max(lo.Map(processes, func(item *process.UnixProcess, index int) int {
		return len(strconv.Itoa(item.PPid()))
	}))

	longestProcessName := lo.MaxBy(processes, func(item *process.UnixProcess, max *process.UnixProcess) bool {
		return len(item.Executable()) > len(max.Executable())
	})

	longestUserName := lo.MaxBy(processes, func(item *process.UnixProcess, max *process.UnixProcess) bool {
		return len(item.User().Username) > len(max.User().Username)
	})

	longestGroupName := lo.MaxBy(processes, func(item *process.UnixProcess, max *process.UnixProcess) bool {
		return len(item.Group().Name) > len(max.Group().Name)
	})

	columns := []table.Column{
		{Title: "Pid", Width: longestPid},
		{Title: "Parent", Width: longestParent},
		{Title: "Name", Width: len(longestProcessName.Executable())},
		{Title: "User", Width: len(longestUserName.User().Username)},
		{Title: "Group", Width: len(longestGroupName.Group().Name)},
		{Title: "State", Width: 8},
	}

	rows := []table.Row{}
	for _, proc := range processes {
		rows = append(rows, table.Row{
			strconv.Itoa(proc.Pid()),
			strconv.Itoa(proc.PPid()),
			proc.Executable(),
			proc.User().Username,
			proc.Group().Name,
			string(proc.State()),
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("#13265C")).
		Bold(false)
	t.SetStyles(s)

	return model{t}
}
