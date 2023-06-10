package process

import (
	"fmt"
	"io/ioutil"
	"os/user"
	"strconv"
	"strings"
)

// UnixProcess is an implementation of Process that contains Unix-specific
// fields and information.
type UnixProcess struct {
	pid   int
	ppid  int
	state string

	user  *user.User
	group *user.Group

	binary string
}

func newUnixProcess(pid int) (*UnixProcess, error) {
	p := &UnixProcess{pid: pid}
	return p, p.RefreshStatus()
}

func (p *UnixProcess) User() *user.User {
	return p.user
}

func (p *UnixProcess) Group() *user.Group {
	return p.group
}

func (p *UnixProcess) Pid() int {
	return p.pid
}

func (p *UnixProcess) PPid() int {
	return p.ppid
}

func (p *UnixProcess) Executable() string {
	return p.binary
}

func (p *UnixProcess) State() string {
	return p.state
}

func (p *UnixProcess) readProcessFile(path string) ([]byte, error) {
	statPath := fmt.Sprintf("/proc/%d/%s", p.pid, path)
	return ioutil.ReadFile(statPath)
}

func (p *UnixProcess) RefreshStatus() error {
	dataBytes, err := p.readProcessFile("status")
	if err != nil {
		return err
	}
	errUnexpectedInput := fmt.Errorf("unexpected input from /proc/%d/status", p.pid)

	for _, line := range strings.Split(string(dataBytes), "\n") {
		fields := strings.Fields(line)
		// Something went wrong here
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			if len(fields) != 5 {
				return fmt.Errorf(line+": %w", errUnexpectedInput)
			}
			user, err := user.LookupId(fields[1])
			if err != nil {
				continue
			}
			p.user = user
		case "Name:":
			p.binary = fields[1]
		case "Gid:":
			if len(fields) != 5 {
				return fmt.Errorf(line+": %w", errUnexpectedInput)
			}
			group, err := user.LookupGroupId(fields[1])
			if err != nil {
				continue
			}
			p.group = group
		case "State:":
			if len(fields) != 3 {
				return fmt.Errorf(line+": %w", errUnexpectedInput)
			}
			p.state = strings.TrimFunc(fields[2], func(r rune) bool {
				return r == '(' || r == ')'
			})
		case "PPid:":
			// TODO: error
			p.ppid, _ = strconv.Atoi(fields[1])
		}
	}

	return nil
}
