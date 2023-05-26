package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

type DnsHeader struct {
	TransactionId uint16
	RD            uint8
	TC            uint8
	AA            uint8
	OpCode        uint8
	QR            uint8
	RCode         uint8
	CD            uint8
	AD            uint8
	Z             uint8
	RA            uint8
	QCount        uint16
	AnsCount      uint16
	AuthCount     uint16
	AddCount      uint16
}

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

	dnsPacketsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("dns_packets", dnsPacketsChannel)
	handleError("Failed creating ring buffer", err)
	defer rb.Stop()
	rb.Poll(300)

	for {
		select {
		case ev := <-dnsPacketsChannel:
			var header DnsHeader
			if err := unmarshal(ev, &header, binary.LittleEndian); err != nil {
				fmt.Printf("Failed unmarshalling binary pattern to DnsHeader: %s", err)
				continue
			}
			fmt.Printf("header: %v\n", header.QR)
		}
	}
}

func handleError(message string, err error) {
	if err == nil {
		return
	}
	fmt.Printf("%s: %s\n", message, err)
	os.Exit(-1)
}

func unmarshal(data []byte, v any, endianess binary.ByteOrder) error {
	return binary.Read(bytes.NewBuffer(data), endianess, v)
}
