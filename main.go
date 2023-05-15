package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

type RxCount struct {
	Bytes   uint64
	Packets uint64
}

func ip2Long(ip string) uint32 {
	var long uint32
	err := binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
	if err != nil {
		return 0
	}
	return long
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

	bpfModule, _ := bpf.NewModuleFromFile("src/xdp.o")
	err := bpfModule.BPFLoadObject()
	if err != nil {
		return
	}

	xdpProg, err := bpfModule.GetProgram("my_program")
	if err != nil {
		fmt.Println(err)
		return
	}
	if xdpProg == nil {
		fmt.Println("XDP program not found")
		return
	}

	_, err = xdpProg.AttachXDP(deviceName)
	handleError("Failed to attach XDP program", err)

	incomingIpMap, err := bpfModule.GetMap("incoming_ip_traffic")
	handleError("Failed to retrieve map incoming_ip_traffic", err)

	select {}

	for {
		// ip := ip2Long("192.168.0.114")
		// if ip == 3232235634 {
		// 	fmt.Println("great")
		// }
		// value, err := incomingIpMap.GetValue(unsafe.Pointer(&ip))
		// if err != nil {
		// 	continue
		// }

		// var rxCount RxCount
		// if err := binary.Read(bytes.NewBuffer(value), binary.LittleEndian, &rxCount); err != nil {
		// 	fmt.Printf("Failed to parse struct value: %v\n", err)
		// 	return
		// }
		// if rxCount.Packets == 0 {
		// 	continue
		// }

		// // Print in kilobytes
		// fmt.Printf("%d KB\n", rxCount.Bytes/(1000))
		time.Sleep(1 * time.Second)
	}
}

func handleError(message string, err error) {
	if err == nil {
		return
	}
	fmt.Printf("%s: %s\n", message, err)
	os.Exit(-1)
}
