// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: teleport/lib/web/terminal/envelope.proto

package terminal

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	golang_proto "github.com/golang/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = golang_proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Envelope is used to wrap and transend and receive messages between the
// web client and proxy.
type Envelope struct {
	// Version is the version of the protocol.
	Version string `protobuf:"bytes,1,opt,name=Version,proto3" json:"Version,omitempty"`
	// Type is the type of message. For version 1 of the protocol this must
	// not be longer than 1 character.
	Type string `protobuf:"bytes,2,opt,name=Type,proto3" json:"Type,omitempty"`
	// Payload is the actual data to send.
	Payload              string   `protobuf:"bytes,3,opt,name=Payload,proto3" json:"Payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Envelope) Reset()         { *m = Envelope{} }
func (m *Envelope) String() string { return proto.CompactTextString(m) }
func (*Envelope) ProtoMessage()    {}
func (*Envelope) Descriptor() ([]byte, []int) {
	return fileDescriptor_016ae8368e6afaa7, []int{0}
}
func (m *Envelope) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Envelope) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Envelope.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Envelope) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Envelope.Merge(m, src)
}
func (m *Envelope) XXX_Size() int {
	return m.Size()
}
func (m *Envelope) XXX_DiscardUnknown() {
	xxx_messageInfo_Envelope.DiscardUnknown(m)
}

var xxx_messageInfo_Envelope proto.InternalMessageInfo

func (m *Envelope) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *Envelope) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *Envelope) GetPayload() string {
	if m != nil {
		return m.Payload
	}
	return ""
}

func init() {
	proto.RegisterType((*Envelope)(nil), "teleport.lib.web.Envelope")
	golang_proto.RegisterType((*Envelope)(nil), "teleport.lib.web.Envelope")
}

func init() {
	proto.RegisterFile("teleport/lib/web/terminal/envelope.proto", fileDescriptor_016ae8368e6afaa7)
}
func init() {
	golang_proto.RegisterFile("teleport/lib/web/terminal/envelope.proto", fileDescriptor_016ae8368e6afaa7)
}

var fileDescriptor_016ae8368e6afaa7 = []byte{
	// 198 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x28, 0x49, 0xcd, 0x49,
	0x2d, 0xc8, 0x2f, 0x2a, 0xd1, 0xcf, 0xc9, 0x4c, 0xd2, 0x2f, 0x4f, 0x4d, 0xd2, 0x2f, 0x49, 0x2d,
	0xca, 0xcd, 0xcc, 0x4b, 0xcc, 0xd1, 0x4f, 0xcd, 0x2b, 0x4b, 0xcd, 0xc9, 0x2f, 0x48, 0xd5, 0x2b,
	0x28, 0xca, 0x2f, 0xc9, 0x17, 0x12, 0x80, 0xa9, 0xd4, 0xcb, 0xc9, 0x4c, 0xd2, 0x2b, 0x4f, 0x4d,
	0x92, 0x12, 0x49, 0xcf, 0x4f, 0xcf, 0x07, 0x4b, 0xea, 0x83, 0x58, 0x10, 0x75, 0x4a, 0x41, 0x5c,
	0x1c, 0xae, 0x50, 0x9d, 0x42, 0x12, 0x5c, 0xec, 0x61, 0xa9, 0x45, 0xc5, 0x99, 0xf9, 0x79, 0x12,
	0x8c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41, 0x30, 0xae, 0x90, 0x10, 0x17, 0x4b, 0x48, 0x65, 0x41, 0xaa,
	0x04, 0x13, 0x58, 0x18, 0xcc, 0x06, 0xa9, 0x0e, 0x48, 0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0x91, 0x60,
	0x86, 0xa8, 0x86, 0x72, 0x9d, 0x5c, 0x4e, 0x3c, 0x92, 0x63, 0xbc, 0xf0, 0x48, 0x8e, 0xf1, 0xc1,
	0x23, 0x39, 0xc6, 0x03, 0x8f, 0xe5, 0x18, 0xa3, 0x8c, 0xd2, 0x33, 0x4b, 0x32, 0x4a, 0x93, 0xf4,
	0x92, 0xf3, 0x73, 0xf5, 0xd3, 0x8b, 0x12, 0xcb, 0x32, 0x4b, 0x12, 0x4b, 0x32, 0xf3, 0x41, 0xce,
	0xc6, 0xe9, 0xa1, 0x24, 0x36, 0xb0, 0x03, 0x8d, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x63, 0x0e,
	0xff, 0x66, 0xf4, 0x00, 0x00, 0x00,
}

func (m *Envelope) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Envelope) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Envelope) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Payload) > 0 {
		i -= len(m.Payload)
		copy(dAtA[i:], m.Payload)
		i = encodeVarintEnvelope(dAtA, i, uint64(len(m.Payload)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Type) > 0 {
		i -= len(m.Type)
		copy(dAtA[i:], m.Type)
		i = encodeVarintEnvelope(dAtA, i, uint64(len(m.Type)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Version) > 0 {
		i -= len(m.Version)
		copy(dAtA[i:], m.Version)
		i = encodeVarintEnvelope(dAtA, i, uint64(len(m.Version)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintEnvelope(dAtA []byte, offset int, v uint64) int {
	offset -= sovEnvelope(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Envelope) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Version)
	if l > 0 {
		n += 1 + l + sovEnvelope(uint64(l))
	}
	l = len(m.Type)
	if l > 0 {
		n += 1 + l + sovEnvelope(uint64(l))
	}
	l = len(m.Payload)
	if l > 0 {
		n += 1 + l + sovEnvelope(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovEnvelope(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozEnvelope(x uint64) (n int) {
	return sovEnvelope(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Envelope) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEnvelope
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Envelope: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Envelope: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEnvelope
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEnvelope
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthEnvelope
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Version = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEnvelope
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEnvelope
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthEnvelope
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Type = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Payload", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEnvelope
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEnvelope
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthEnvelope
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Payload = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipEnvelope(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthEnvelope
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipEnvelope(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowEnvelope
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowEnvelope
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowEnvelope
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthEnvelope
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupEnvelope
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthEnvelope
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthEnvelope        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowEnvelope          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupEnvelope = fmt.Errorf("proto: unexpected end of group")
)
