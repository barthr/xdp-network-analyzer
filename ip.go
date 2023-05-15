package main

import (
	"bytes"
	"encoding/binary"
	"net"
)

func IpToUint32(ip string) (uint32, error) {
	var long uint32
	return long, binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
}

func Uint32ToIp(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
