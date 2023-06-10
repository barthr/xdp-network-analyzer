package main

import (
	"fmt"
	"os"
	"xdp-network-analyzer/repository"
	"xdp-network-analyzer/ui"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide device name")
		os.Exit(-1)
	}

	deviceName := os.Args[1]
	if deviceName == "" {
		fmt.Println("Please provide device name")
		os.Exit(-1)
	}

	bpfModule, err := bpf.NewModuleFromFile("src/xdp.o")
	handleError("Failed loading xdp.o module from file", err)

	err = bpfModule.BPFLoadObject()
	handleError("Failed loading bpf object", err)

	xdpProg, err := bpfModule.GetProgram("my_program")
	handleError("Failed retrieving program", err)

	_, err = xdpProg.AttachXDP(deviceName)
	handleError("Failed to attach XDP program", err)

	repository.Pid, err = repository.NewPidRepository(bpfModule, "pid_monitor_map")
	handleError("Failed creating pid repository", err)

	ui.StartTea()
}

func handleError(message string, err error) {
	if err == nil {
		return
	}
	fmt.Printf("%s: %s\n", message, err)
	os.Exit(-1)
}
