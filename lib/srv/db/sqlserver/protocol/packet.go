/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/gravitational/trace"
)

// PacketHeader represents a 8-byte packet header.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7af53667-1b72-4703-8258-7984e838f746
//
// Note: the order of fields in the struct matters as it gets unpacked from the
// binary stream.
type PacketHeader struct {
	Type     uint8
	Status   uint8
	Length   uint16 // network byte order (big-endian)
	SPID     uint16 // network byte order (big-endian)
	PacketID uint8
	Window   uint8
}

// Marshal marshals the packet header to the wire protocol byte representation.
func (h *PacketHeader) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, packetHeaderSize))
	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil, trace.Wrap(err)
	}
	return buf.Bytes(), nil
}

type Packet interface {
	Bytes() []byte
	Data() []byte
	Header() PacketHeader
	Type() uint8
}

type packet struct {
	header PacketHeader
	data   []byte
	raw    bytes.Buffer
}

// Bytes returns raw packet bytes.
func (g packet) Bytes() []byte {
	return g.raw.Bytes()
}

// Data is the packet data bytes without header.
func (g packet) Data() []byte {
	return g.data
}

// Header is the parsed packet header.
func (g packet) Header() PacketHeader {
	return g.header
}

// Type is the parsed packet header.
func (g packet) Type() uint8 {
	return g.header.Type
}

// ReadPacket reads a single full packet from the reader.
func ReadPacket(r io.Reader) (Packet, error) {
	var buff bytes.Buffer
	tr := io.TeeReader(r, &buff)
	// Read 8-byte packet header.
	var headerBytes [packetHeaderSize]byte
	if _, err := io.ReadFull(tr, headerBytes[:]); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	// Unmarshal packet header from the binary form.
	var header PacketHeader
	if err := binary.Read(bytes.NewReader(headerBytes[:]), binary.BigEndian, &header); err != nil {
		return nil, trace.Wrap(err)
	}

	// Read packet data. Packet length includes header.
	dataBytes := make([]byte, header.Length-packetHeaderSize)
	if _, err := io.ReadFull(tr, dataBytes); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	p := &packet{
		header: header,
		data:   dataBytes,
		raw:    buff,
	}

	switch p.Type() {
	case PacketTypeRPCRequest:
		sqlBatch, err := toRPCRequest(p)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return sqlBatch, nil
	case PacketTypeSQLBatch:
		rpcRequest, err := toSQLBatch(p)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return rpcRequest, nil
	default:
		return p, nil
	}

}

// makePacket prepends header to the provided packet data.
func makePacket(pktType uint8, pktData []byte) ([]byte, error) {
	header := PacketHeader{
		Type:   pktType,
		Status: packetStatusLast,
		Length: uint16(packetHeaderSize + len(pktData)),
	}

	headerBytes, err := header.Marshal()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return append(headerBytes, pktData...), nil
}
