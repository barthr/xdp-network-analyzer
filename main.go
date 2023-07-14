package main

import (
	"fmt"
	"os"
	"syscall"
	"xdp-network-analyzer/bpfutil"
	"xdp-network-analyzer/repository"
	"xdp-network-analyzer/ui"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
)

type EventType uint32

func (e EventType) String() string {
	switch e {
	case INVOKE_RETRIEVE_HOSTNAME:
		return "INVOKE_RETRIEVE_HOSTNAME"
	case INVOKE_RETRIEVE_HOSTNAME_RETURN:
		return "INVOKE_RETRIEVE_HOSTNAME_RETURN"
	case DNS_REQUEST_PACKET:
		return "DNS_REQUEST_PACKET"
	case DNS_RESPONSE_PACKET:
		return "DNS_RESPONSE_PACKET"
	default:
		return ""
	}
}

const (
	INVOKE_RETRIEVE_HOSTNAME EventType = iota
	INVOKE_RETRIEVE_HOSTNAME_RETURN
	DNS_REQUEST_PACKET
	DNS_RESPONSE_PACKET
)

type dnsEvent struct {
	EventType EventType
	Pid       uint32
	Hostname  [256]byte
}

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

	err := bpfutil.LoadDnsLookupModule("src/dns_lookup_probe.o")
	handleError("Failed loading dns module from file", err)

	buffer, err := bpfutil.NewRingBuffer[dnsEvent](bpfutil.DnsModule, "dns_events")
	handleError("Failed loading rb", err)

	tcModule, err := bpfutil.LoadModuleFromFile("src/dns_network.o")
	handleError("Failed loading dns network module from file", err)

	tc := bpfutil.Tc{
		InterfaceName: deviceName,
	}
	defer tc.Close()

	err = tc.LoadProgram(tcModule, "my_program")
	handleError("Failed loading dns network program", err)

	err = tc.Attach(bpf.BPFTcEgress)
	handleError("Failed attaching tc program", err)

	go func() {
		err = buffer.Listen(func(elem dnsEvent) {
			fmt.Printf("received event: %s, Pid: %d Hostname: %s\n", elem.EventType, elem.Pid, elem.Hostname)
		})
		handleError("Failed loading rb", err)
	}()

	//err = entryProbe.LoadProgram(bpfModule, "inspect_dns_lookup")
	//handleError("failed loading program", err)

	//err = entryProbe.Attach(bpfutil.PROBE_TYPE_ENTRY)
	//handleError("Failed loading uprobe", err)
	//defer entryProbe.Detach()
	//
	//returnProbe := &bpfutil.Uprobe{
	//	Executable: "/lib64/libc.so.6",
	//	Symbol:     "getaddrinfo",
	//}
	//err = returnProbe.LoadProgram(bpfModule, "inspect_dns_response")
	//handleError("failed loading program", err)
	//
	//err = returnProbe.Attach(bpfutil.PROBE_TYPE_RETURN)
	//handleError("Failed loading uretprobe", err)
	//defer returnProbe.Detach()

	// bpfModule, err := bpf.NewModuleFromFile("src/xdp.o")
	// handleError("Failed loading xdp.o module from file", err)

	// defer bpfModule.Close()

	// err = bpfModule.BPFLoadObject()
	// handleError("Failed loading bpf object", err)

	// tcProg, err := bpfModule.GetProgram("my_program")
	// handleError("Failed retrieving program", err)

	// socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	// handleError("Failed opening socket", err)
	// defer syscall.Close(socketFd)

	// if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, sockFilter.FileDescriptor()); err != nil {
	// 	log.Panic(err)
	// }
	// defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, sockFilter.FileDescriptor())

	// hook := bpfModule.TcHookInit()
	// err = hook.SetInterfaceByName(deviceName)
	// handleError("Failed to set tc hook on interface lo", err)

	// hook.SetAttachPoint(bpf.BPFTcEgress)
	// err = hook.Create()
	// if err != nil {
	// 	if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
	// 		fmt.Fprintf(os.Stderr, "tc hook create: %v\n", err)
	// 	}
	// }
	// var tcOpts bpf.TcOpts
	// tcOpts.ProgFd = tcProg.FileDescriptor()
	// err = hook.Attach(&tcOpts)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// 	os.Exit(-1)
	// }

	// // _, err = xdpProg.AttachXDP(deviceName)
	// // handleError("Failed to attach XDP program", err)

	repository.Pid, err = repository.NewPidRepository(bpfutil.DnsModule, "pid_monitor_map")
	handleError("Failed creating Pid repository", err)

	ui.StartTea()
}

func handleError(message string, err error) {
	if err == nil {
		return
	}
	fmt.Printf("%s: %s\n", message, err)
	os.Exit(-1)
}
