// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: teleport/mfa/v1/mfa.proto

package mfav1

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

// ChallengeScope is a scope authorized by an MFA challenge resolution.
type ChallengeScope int32

const (
	// Scope unknown or not specified.
	ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED ChallengeScope = 0
	// Standard webauthn login.
	ChallengeScope_CHALLENGE_SCOPE_LOGIN ChallengeScope = 1
	// Passwordless webauthn login.
	ChallengeScope_CHALLENGE_SCOPE_PASSWORDLESS_LOGIN ChallengeScope = 2
	// Headless login.
	ChallengeScope_CHALLENGE_SCOPE_HEADLESS_LOGIN ChallengeScope = 3
	// MFA device management.
	ChallengeScope_CHALLENGE_SCOPE_MANAGE_DEVICES ChallengeScope = 4
	// Account recovery.
	ChallengeScope_CHALLENGE_SCOPE_ACCOUNT_RECOVERY ChallengeScope = 5
	// Used for per-session MFA and moderated session presence checks.
	ChallengeScope_CHALLENGE_SCOPE_USER_SESSION ChallengeScope = 6
	// Used for various administrative actions, such as adding, updating, or
	// deleting administrative resources (users, roles, etc.).
	//
	// Note: this scope should not be used for new MFA capabilities that have
	// more precise scope. Instead, new scopes should be added. This scope may
	// also be split into multiple smaller scopes in the future.
	ChallengeScope_CHALLENGE_SCOPE_ADMIN_ACTION ChallengeScope = 7
	// Used for changing user's password.
	ChallengeScope_CHALLENGE_SCOPE_CHANGE_PASSWORD ChallengeScope = 8
)

var ChallengeScope_name = map[int32]string{
	0: "CHALLENGE_SCOPE_UNSPECIFIED",
	1: "CHALLENGE_SCOPE_LOGIN",
	2: "CHALLENGE_SCOPE_PASSWORDLESS_LOGIN",
	3: "CHALLENGE_SCOPE_HEADLESS_LOGIN",
	4: "CHALLENGE_SCOPE_MANAGE_DEVICES",
	5: "CHALLENGE_SCOPE_ACCOUNT_RECOVERY",
	6: "CHALLENGE_SCOPE_USER_SESSION",
	7: "CHALLENGE_SCOPE_ADMIN_ACTION",
	8: "CHALLENGE_SCOPE_CHANGE_PASSWORD",
}

var ChallengeScope_value = map[string]int32{
	"CHALLENGE_SCOPE_UNSPECIFIED":        0,
	"CHALLENGE_SCOPE_LOGIN":              1,
	"CHALLENGE_SCOPE_PASSWORDLESS_LOGIN": 2,
	"CHALLENGE_SCOPE_HEADLESS_LOGIN":     3,
	"CHALLENGE_SCOPE_MANAGE_DEVICES":     4,
	"CHALLENGE_SCOPE_ACCOUNT_RECOVERY":   5,
	"CHALLENGE_SCOPE_USER_SESSION":       6,
	"CHALLENGE_SCOPE_ADMIN_ACTION":       7,
	"CHALLENGE_SCOPE_CHANGE_PASSWORD":    8,
}

func (x ChallengeScope) String() string {
	return proto.EnumName(ChallengeScope_name, int32(x))
}

func (ChallengeScope) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{0}
}

// ChallengeAllowReuse determines whether an MFA challenge response can be used
// to authenticate the user more than once until the challenge expires.
//
// Reuse is only permitted for specific actions by the discretion of the server.
// See the server implementation for details.
type ChallengeAllowReuse int32

const (
	// Reuse unspecified, treated as CHALLENGE_ALLOW_REUSE_NO.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_UNSPECIFIED ChallengeAllowReuse = 0
	// Reuse is permitted.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES ChallengeAllowReuse = 1
	// Reuse is not permitted.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO ChallengeAllowReuse = 2
)

var ChallengeAllowReuse_name = map[int32]string{
	0: "CHALLENGE_ALLOW_REUSE_UNSPECIFIED",
	1: "CHALLENGE_ALLOW_REUSE_YES",
	2: "CHALLENGE_ALLOW_REUSE_NO",
}

var ChallengeAllowReuse_value = map[string]int32{
	"CHALLENGE_ALLOW_REUSE_UNSPECIFIED": 0,
	"CHALLENGE_ALLOW_REUSE_YES":         1,
	"CHALLENGE_ALLOW_REUSE_NO":          2,
}

func (x ChallengeAllowReuse) String() string {
	return proto.EnumName(ChallengeAllowReuse_name, int32(x))
}

func (ChallengeAllowReuse) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{1}
}

// ChallengeExtensions contains MFA challenge extensions used by Teleport
// during MFA authentication.
type ChallengeExtensions struct {
	// Scope is an authorization scope for this MFA challenge.
	// Required.
	Scope ChallengeScope `protobuf:"varint,1,opt,name=scope,proto3,enum=teleport.mfa.v1.ChallengeScope" json:"scope,omitempty"`
	// AllowReuse determines whether the MFA challenge allows reuse.
	// Defaults to CHALLENGE_ALLOW_REUSE_NO.
	//
	// Note that reuse is only permitted for specific actions by the discretion
	// of the server. See the server implementation for details.
	AllowReuse ChallengeAllowReuse `protobuf:"varint,2,opt,name=allow_reuse,json=allowReuse,proto3,enum=teleport.mfa.v1.ChallengeAllowReuse" json:"allow_reuse,omitempty"`
	// User verification requirement for the challenge.
	//
	// * https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement.
	// * https://pkg.go.dev/github.com/go-webauthn/webauthn/protocol#UserVerificationRequirement.
	//
	// Optional. Empty is equivalent to "discouraged".
	UserVerificationRequirement string   `protobuf:"bytes,3,opt,name=user_verification_requirement,json=userVerificationRequirement,proto3" json:"user_verification_requirement,omitempty"`
	XXX_NoUnkeyedLiteral        struct{} `json:"-"`
	XXX_unrecognized            []byte   `json:"-"`
	XXX_sizecache               int32    `json:"-"`
}

func (m *ChallengeExtensions) Reset()         { *m = ChallengeExtensions{} }
func (m *ChallengeExtensions) String() string { return proto.CompactTextString(m) }
func (*ChallengeExtensions) ProtoMessage()    {}
func (*ChallengeExtensions) Descriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{0}
}
func (m *ChallengeExtensions) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ChallengeExtensions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ChallengeExtensions.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ChallengeExtensions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChallengeExtensions.Merge(m, src)
}
func (m *ChallengeExtensions) XXX_Size() int {
	return m.Size()
}
func (m *ChallengeExtensions) XXX_DiscardUnknown() {
	xxx_messageInfo_ChallengeExtensions.DiscardUnknown(m)
}

var xxx_messageInfo_ChallengeExtensions proto.InternalMessageInfo

func (m *ChallengeExtensions) GetScope() ChallengeScope {
	if m != nil {
		return m.Scope
	}
	return ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED
}

func (m *ChallengeExtensions) GetAllowReuse() ChallengeAllowReuse {
	if m != nil {
		return m.AllowReuse
	}
	return ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_UNSPECIFIED
}

func (m *ChallengeExtensions) GetUserVerificationRequirement() string {
	if m != nil {
		return m.UserVerificationRequirement
	}
	return ""
}

func init() {
	proto.RegisterEnum("teleport.mfa.v1.ChallengeScope", ChallengeScope_name, ChallengeScope_value)
	golang_proto.RegisterEnum("teleport.mfa.v1.ChallengeScope", ChallengeScope_name, ChallengeScope_value)
	proto.RegisterEnum("teleport.mfa.v1.ChallengeAllowReuse", ChallengeAllowReuse_name, ChallengeAllowReuse_value)
	golang_proto.RegisterEnum("teleport.mfa.v1.ChallengeAllowReuse", ChallengeAllowReuse_name, ChallengeAllowReuse_value)
	proto.RegisterType((*ChallengeExtensions)(nil), "teleport.mfa.v1.ChallengeExtensions")
	golang_proto.RegisterType((*ChallengeExtensions)(nil), "teleport.mfa.v1.ChallengeExtensions")
}

func init() { proto.RegisterFile("teleport/mfa/v1/mfa.proto", fileDescriptor_eb9e544d66a5853a) }
func init() { golang_proto.RegisterFile("teleport/mfa/v1/mfa.proto", fileDescriptor_eb9e544d66a5853a) }

var fileDescriptor_eb9e544d66a5853a = []byte{
	// 473 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0xd3, 0xcf, 0x6e, 0xd3, 0x30,
	0x00, 0x06, 0x70, 0xdc, 0xb1, 0x01, 0x46, 0x1a, 0x91, 0x01, 0xa9, 0x65, 0x5b, 0x5a, 0xca, 0x40,
	0xd3, 0x0e, 0x89, 0x0a, 0xe2, 0xc4, 0xc9, 0x73, 0x4d, 0x1b, 0x29, 0x4b, 0x2a, 0x7b, 0xed, 0xb4,
	0x5d, 0xac, 0xac, 0x72, 0xb3, 0x48, 0x69, 0x5c, 0x92, 0x34, 0xc0, 0xdb, 0x71, 0x44, 0xe2, 0xc2,
	0x8d, 0x2b, 0x2a, 0x2f, 0x82, 0xdc, 0xd2, 0x3f, 0x84, 0x72, 0x8a, 0x93, 0xef, 0xf7, 0x45, 0x71,
	0x6c, 0xc3, 0x5a, 0x2e, 0x63, 0x39, 0x51, 0x69, 0x6e, 0x8f, 0x47, 0x81, 0x5d, 0xb4, 0xf4, 0xc5,
	0x9a, 0xa4, 0x2a, 0x57, 0xe8, 0xd1, 0x32, 0xb2, 0xf4, 0xb3, 0xa2, 0xf5, 0xec, 0x49, 0xa8, 0x42,
	0x35, 0xcf, 0x6c, 0x3d, 0x5a, 0xb0, 0xe6, 0x0f, 0x00, 0x1f, 0x93, 0xdb, 0x20, 0x8e, 0x65, 0x12,
	0x4a, 0xfa, 0x29, 0x97, 0x49, 0x16, 0xa9, 0x24, 0x43, 0x6f, 0xe1, 0x6e, 0x36, 0x54, 0x13, 0x59,
	0x05, 0x0d, 0x70, 0xb2, 0xff, 0xba, 0x6e, 0x95, 0x5e, 0x67, 0xad, 0x4a, 0x5c, 0x33, 0xb6, 0xd0,
	0x88, 0xc2, 0x87, 0x41, 0x1c, 0xab, 0x8f, 0x22, 0x95, 0xd3, 0x4c, 0x56, 0x2b, 0xf3, 0xf2, 0xf1,
	0xff, 0xcb, 0x58, 0x63, 0xa6, 0x2d, 0x83, 0xc1, 0x6a, 0x8c, 0xce, 0xe0, 0xd1, 0x34, 0x93, 0xa9,
	0x28, 0x64, 0x1a, 0x8d, 0xa2, 0x61, 0x90, 0x47, 0x2a, 0x11, 0xa9, 0xfc, 0x30, 0x8d, 0x52, 0x39,
	0x96, 0x49, 0x5e, 0xdd, 0x69, 0x80, 0x93, 0x07, 0xec, 0x40, 0xa3, 0xc1, 0x86, 0x61, 0x6b, 0x72,
	0xfa, 0xad, 0x02, 0xf7, 0xff, 0xfe, 0x48, 0x54, 0x87, 0x07, 0xa4, 0x8b, 0x5d, 0x97, 0x7a, 0x1d,
	0x2a, 0x38, 0xf1, 0x7b, 0x54, 0xf4, 0x3d, 0xde, 0xa3, 0xc4, 0x79, 0xef, 0xd0, 0xb6, 0x71, 0x07,
	0xd5, 0xe0, 0xd3, 0x32, 0x70, 0xfd, 0x8e, 0xe3, 0x19, 0x00, 0xbd, 0x82, 0xcd, 0x72, 0xd4, 0xc3,
	0x9c, 0x5f, 0xfa, 0xac, 0xed, 0x52, 0xce, 0xff, 0xb8, 0x0a, 0x6a, 0x42, 0xb3, 0xec, 0xba, 0x14,
	0x6f, 0x9a, 0x9d, 0x6d, 0xe6, 0x1c, 0x7b, 0xb8, 0x43, 0x45, 0x9b, 0x0e, 0x1c, 0x42, 0xb9, 0x71,
	0x17, 0x1d, 0xc3, 0x46, 0xd9, 0x60, 0x42, 0xfc, 0xbe, 0x77, 0x21, 0x18, 0x25, 0xfe, 0x80, 0xb2,
	0x2b, 0x63, 0x17, 0x35, 0xe0, 0xe1, 0x3f, 0x33, 0xe2, 0x94, 0x09, 0x4e, 0x39, 0x77, 0x7c, 0xcf,
	0xd8, 0xdb, 0x26, 0x70, 0xfb, 0xdc, 0xf1, 0x04, 0x26, 0x17, 0x5a, 0xdc, 0x43, 0x2f, 0x60, 0xbd,
	0x2c, 0x48, 0x17, 0xeb, 0x9b, 0xe5, 0x04, 0x8d, 0xfb, 0xa7, 0x9f, 0x37, 0xb6, 0xc9, 0x7a, 0xd1,
	0xd0, 0x4b, 0xf8, 0x7c, 0xdd, 0xc5, 0xae, 0xeb, 0x5f, 0x0a, 0x46, 0xfb, 0xbc, 0xfc, 0x5f, 0x8f,
	0x60, 0x6d, 0x3b, 0xbb, 0xa2, 0xdc, 0x00, 0xe8, 0x10, 0x56, 0xb7, 0xc7, 0x9e, 0x6f, 0x54, 0xce,
	0xae, 0xbf, 0xce, 0x4c, 0xf0, 0x7d, 0x66, 0x82, 0x9f, 0x33, 0x13, 0x7c, 0xf9, 0x65, 0x82, 0xeb,
	0x6e, 0x18, 0xe5, 0xb7, 0xd3, 0x1b, 0x6b, 0xa8, 0xc6, 0x76, 0x98, 0x06, 0x45, 0x94, 0xcf, 0x57,
	0x3f, 0x88, 0xed, 0xd5, 0x79, 0x08, 0x26, 0x91, 0x1d, 0xca, 0xc4, 0x5e, 0x6e, 0x78, 0xbb, 0x74,
	0x52, 0xde, 0x8d, 0x47, 0x41, 0xd1, 0xba, 0xd9, 0x9b, 0xe7, 0x6f, 0x7e, 0x07, 0x00, 0x00, 0xff,
	0xff, 0x0a, 0xd9, 0xea, 0x39, 0x49, 0x03, 0x00, 0x00,
}

func (m *ChallengeExtensions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ChallengeExtensions) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ChallengeExtensions) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.UserVerificationRequirement) > 0 {
		i -= len(m.UserVerificationRequirement)
		copy(dAtA[i:], m.UserVerificationRequirement)
		i = encodeVarintMfa(dAtA, i, uint64(len(m.UserVerificationRequirement)))
		i--
		dAtA[i] = 0x1a
	}
	if m.AllowReuse != 0 {
		i = encodeVarintMfa(dAtA, i, uint64(m.AllowReuse))
		i--
		dAtA[i] = 0x10
	}
	if m.Scope != 0 {
		i = encodeVarintMfa(dAtA, i, uint64(m.Scope))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintMfa(dAtA []byte, offset int, v uint64) int {
	offset -= sovMfa(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ChallengeExtensions) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Scope != 0 {
		n += 1 + sovMfa(uint64(m.Scope))
	}
	if m.AllowReuse != 0 {
		n += 1 + sovMfa(uint64(m.AllowReuse))
	}
	l = len(m.UserVerificationRequirement)
	if l > 0 {
		n += 1 + l + sovMfa(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovMfa(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMfa(x uint64) (n int) {
	return sovMfa(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ChallengeExtensions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMfa
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
			return fmt.Errorf("proto: ChallengeExtensions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ChallengeExtensions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Scope", wireType)
			}
			m.Scope = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Scope |= ChallengeScope(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowReuse", wireType)
			}
			m.AllowReuse = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AllowReuse |= ChallengeAllowReuse(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserVerificationRequirement", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
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
				return ErrInvalidLengthMfa
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMfa
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.UserVerificationRequirement = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMfa(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMfa
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
func skipMfa(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMfa
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
					return 0, ErrIntOverflowMfa
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
					return 0, ErrIntOverflowMfa
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
				return 0, ErrInvalidLengthMfa
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMfa
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMfa
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMfa        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMfa          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMfa = fmt.Errorf("proto: unexpected end of group")
)
