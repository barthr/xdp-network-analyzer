package bpfutil

import (
	"bytes"
	"encoding/binary"
	bpf "github.com/aquasecurity/libbpfgo"
)

type RingBuffer[T any] struct {
	rb             *bpf.RingBuffer
	receiveChannel chan []byte
}

func NewRingBuffer[T any](bpfModule *bpf.Module, mapName string) (*RingBuffer[T], error) {
	rc := make(chan []byte)
	rb, err := bpfModule.InitRingBuf(mapName, rc)
	if err != nil {
		return nil, err
	}
	return &RingBuffer[T]{
		rb:             rb,
		receiveChannel: rc,
	}, nil
}

func (rb *RingBuffer[T]) Listen(consumer func(elem T)) error {
	defer rb.rb.Stop()
	rb.rb.Poll(100)

	for data := range rb.receiveChannel {
		var record T
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &record); err != nil {
			return err
		}
		consumer(record)
	}

	return nil
}
