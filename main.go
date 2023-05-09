package main

import (
	"fmt"
	"os"

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
	if err != nil {
		fmt.Println(err)
		return
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("ringbuf_map", eventsChannel)
	if err != nil {
		fmt.Println(err)
		return
	}
	rb.Poll(300)

	defer rb.Stop()
	defer rb.Close()
	for {
		b := <-eventsChannel
		// convert byte array to printable string
		// u := binary.LittleEndian.Uint32(b)
		fmt.Println(string(b))
	}
}
