// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/dbobject/v1/dbobject.proto

package dbobjectv1

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// DatabaseObject represents a database object that can be imported into Teleport.
// An example of such object would be a database table, along with various metadata.
// For rationale behind this type, see the RFD 151.
type DatabaseObject struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The kind of resource represented.
	Kind string `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	// Mandatory field for all resources. Not populated for this resource type.
	SubKind string `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// The version of the resource being represented.
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	// Common metadata that all resources share.
	Metadata *v1.Metadata `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// Specification for the database object.
	Spec *DatabaseObjectSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *DatabaseObject) Reset() {
	*x = DatabaseObject{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobject_v1_dbobject_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObject) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObject) ProtoMessage() {}

func (x *DatabaseObject) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobject_v1_dbobject_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObject.ProtoReflect.Descriptor instead.
func (*DatabaseObject) Descriptor() ([]byte, []int) {
	return file_teleport_dbobject_v1_dbobject_proto_rawDescGZIP(), []int{0}
}

func (x *DatabaseObject) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *DatabaseObject) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *DatabaseObject) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *DatabaseObject) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *DatabaseObject) GetSpec() *DatabaseObjectSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// DatabaseObjectSpec is the spec for the database object.
type DatabaseObjectSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The protocol used to connect to the database (e.g., postgres). Required.
	Protocol string `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	// The name of the database service that this object belongs to. Required.
	DatabaseServiceName string `protobuf:"bytes,2,opt,name=database_service_name,json=databaseServiceName,proto3" json:"database_service_name,omitempty"`
	// The kind of database object (e.g., table, view). Required.
	ObjectKind string `protobuf:"bytes,3,opt,name=object_kind,json=objectKind,proto3" json:"object_kind,omitempty"`
	// The database containing the object. Optional.
	Database string `protobuf:"bytes,4,opt,name=database,proto3" json:"database,omitempty"`
	// The schema containing the object (if applicable). Optional.
	Schema string `protobuf:"bytes,5,opt,name=schema,proto3" json:"schema,omitempty"`
	// The name of the object. Required.
	Name string `protobuf:"bytes,6,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DatabaseObjectSpec) Reset() {
	*x = DatabaseObjectSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobject_v1_dbobject_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectSpec) ProtoMessage() {}

func (x *DatabaseObjectSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobject_v1_dbobject_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectSpec.ProtoReflect.Descriptor instead.
func (*DatabaseObjectSpec) Descriptor() ([]byte, []int) {
	return file_teleport_dbobject_v1_dbobject_proto_rawDescGZIP(), []int{1}
}

func (x *DatabaseObjectSpec) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *DatabaseObjectSpec) GetDatabaseServiceName() string {
	if x != nil {
		return x.DatabaseServiceName
	}
	return ""
}

func (x *DatabaseObjectSpec) GetObjectKind() string {
	if x != nil {
		return x.ObjectKind
	}
	return ""
}

func (x *DatabaseObjectSpec) GetDatabase() string {
	if x != nil {
		return x.Database
	}
	return ""
}

func (x *DatabaseObjectSpec) GetSchema() string {
	if x != nil {
		return x.Schema
	}
	return ""
}

func (x *DatabaseObjectSpec) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_teleport_dbobject_v1_dbobject_proto protoreflect.FileDescriptor

var file_teleport_dbobject_v1_dbobject_proto_rawDesc = []byte{
	0x0a, 0x23, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x62, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd1,
	0x01, 0x0a, 0x0e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64,
	0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76,
	0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x12, 0x3c, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61,
	0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70,
	0x65, 0x63, 0x22, 0xcd, 0x01, 0x0a, 0x12, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x70, 0x65, 0x63, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x32, 0x0a, 0x15, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
	0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x61,
	0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x64, 0x61,
	0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x42, 0x54, 0x5a, 0x52, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x64, 0x62,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_dbobject_v1_dbobject_proto_rawDescOnce sync.Once
	file_teleport_dbobject_v1_dbobject_proto_rawDescData = file_teleport_dbobject_v1_dbobject_proto_rawDesc
)

func file_teleport_dbobject_v1_dbobject_proto_rawDescGZIP() []byte {
	file_teleport_dbobject_v1_dbobject_proto_rawDescOnce.Do(func() {
		file_teleport_dbobject_v1_dbobject_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_dbobject_v1_dbobject_proto_rawDescData)
	})
	return file_teleport_dbobject_v1_dbobject_proto_rawDescData
}

var file_teleport_dbobject_v1_dbobject_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_teleport_dbobject_v1_dbobject_proto_goTypes = []interface{}{
	(*DatabaseObject)(nil),     // 0: teleport.dbobject.v1.DatabaseObject
	(*DatabaseObjectSpec)(nil), // 1: teleport.dbobject.v1.DatabaseObjectSpec
	(*v1.Metadata)(nil),        // 2: teleport.header.v1.Metadata
}
var file_teleport_dbobject_v1_dbobject_proto_depIdxs = []int32{
	2, // 0: teleport.dbobject.v1.DatabaseObject.metadata:type_name -> teleport.header.v1.Metadata
	1, // 1: teleport.dbobject.v1.DatabaseObject.spec:type_name -> teleport.dbobject.v1.DatabaseObjectSpec
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_dbobject_v1_dbobject_proto_init() }
func file_teleport_dbobject_v1_dbobject_proto_init() {
	if File_teleport_dbobject_v1_dbobject_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_dbobject_v1_dbobject_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObject); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_dbobject_v1_dbobject_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectSpec); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_dbobject_v1_dbobject_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_dbobject_v1_dbobject_proto_goTypes,
		DependencyIndexes: file_teleport_dbobject_v1_dbobject_proto_depIdxs,
		MessageInfos:      file_teleport_dbobject_v1_dbobject_proto_msgTypes,
	}.Build()
	File_teleport_dbobject_v1_dbobject_proto = out.File
	file_teleport_dbobject_v1_dbobject_proto_rawDesc = nil
	file_teleport_dbobject_v1_dbobject_proto_goTypes = nil
	file_teleport_dbobject_v1_dbobject_proto_depIdxs = nil
}
