//
// Teleport
// Copyright (C) 2024  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        (unknown)
// source: accessgraph/v1alpha/azure.proto

package accessgraphv1alpha

import (
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

// AzureResourceList is a list of Azure resources
type AzureResourceList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Resources []*AzureResource `protobuf:"bytes,1,rep,name=resources,proto3" json:"resources,omitempty"`
}

func (x *AzureResourceList) Reset() {
	*x = AzureResourceList{}
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AzureResourceList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AzureResourceList) ProtoMessage() {}

func (x *AzureResourceList) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AzureResourceList.ProtoReflect.Descriptor instead.
func (*AzureResourceList) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_azure_proto_rawDescGZIP(), []int{0}
}

func (x *AzureResourceList) GetResources() []*AzureResource {
	if x != nil {
		return x.Resources
	}
	return nil
}

// AWSResource is a list of AWS resources supported by the access graph.
type AzureResource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Resource:
	//
	//	*AzureResource_VirtualMachine
	Resource isAzureResource_Resource `protobuf_oneof:"resource"`
}

func (x *AzureResource) Reset() {
	*x = AzureResource{}
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AzureResource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AzureResource) ProtoMessage() {}

func (x *AzureResource) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AzureResource.ProtoReflect.Descriptor instead.
func (*AzureResource) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_azure_proto_rawDescGZIP(), []int{1}
}

func (m *AzureResource) GetResource() isAzureResource_Resource {
	if m != nil {
		return m.Resource
	}
	return nil
}

func (x *AzureResource) GetVirtualMachine() *AzureVirtualMachine {
	if x, ok := x.GetResource().(*AzureResource_VirtualMachine); ok {
		return x.VirtualMachine
	}
	return nil
}

type isAzureResource_Resource interface {
	isAzureResource_Resource()
}

type AzureResource_VirtualMachine struct {
	VirtualMachine *AzureVirtualMachine `protobuf:"bytes,1,opt,name=virtual_machine,json=virtualMachine,proto3,oneof"`
}

func (*AzureResource_VirtualMachine) isAzureResource_Resource() {}

// AzureVirtualMachine is an Azure virtual machine
type AzureVirtualMachine struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VirtualMachineId string `protobuf:"bytes,1,opt,name=virtual_machine_id,json=virtualMachineId,proto3" json:"virtual_machine_id,omitempty"`
	Name             string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *AzureVirtualMachine) Reset() {
	*x = AzureVirtualMachine{}
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AzureVirtualMachine) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AzureVirtualMachine) ProtoMessage() {}

func (x *AzureVirtualMachine) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_azure_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AzureVirtualMachine.ProtoReflect.Descriptor instead.
func (*AzureVirtualMachine) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_azure_proto_rawDescGZIP(), []int{2}
}

func (x *AzureVirtualMachine) GetVirtualMachineId() string {
	if x != nil {
		return x.VirtualMachineId
	}
	return ""
}

func (x *AzureVirtualMachine) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_accessgraph_v1alpha_azure_proto protoreflect.FileDescriptor

var file_accessgraph_v1alpha_azure_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x61, 0x7a, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x13, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x22, 0x55, 0x0a, 0x11, 0x41, 0x7a, 0x75, 0x72, 0x65, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x40, 0x0a, 0x09, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22,
	0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2e, 0x41, 0x7a, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x52, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x22, 0x70, 0x0a,
	0x0d, 0x41, 0x7a, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x53,
	0x0a, 0x0f, 0x76, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x5f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x41, 0x7a,
	0x75, 0x72, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e,
	0x65, 0x48, 0x00, 0x52, 0x0e, 0x76, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x4d, 0x61, 0x63, 0x68,
	0x69, 0x6e, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22,
	0x57, 0x0a, 0x13, 0x41, 0x7a, 0x75, 0x72, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x4d,
	0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x12, 0x2c, 0x0a, 0x12, 0x76, 0x69, 0x72, 0x74, 0x75, 0x61,
	0x6c, 0x5f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x10, 0x76, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x4d, 0x61, 0x63, 0x68, 0x69,
	0x6e, 0x65, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x57, 0x5a, 0x55, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65,
	0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_accessgraph_v1alpha_azure_proto_rawDescOnce sync.Once
	file_accessgraph_v1alpha_azure_proto_rawDescData = file_accessgraph_v1alpha_azure_proto_rawDesc
)

func file_accessgraph_v1alpha_azure_proto_rawDescGZIP() []byte {
	file_accessgraph_v1alpha_azure_proto_rawDescOnce.Do(func() {
		file_accessgraph_v1alpha_azure_proto_rawDescData = protoimpl.X.CompressGZIP(file_accessgraph_v1alpha_azure_proto_rawDescData)
	})
	return file_accessgraph_v1alpha_azure_proto_rawDescData
}

var file_accessgraph_v1alpha_azure_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_accessgraph_v1alpha_azure_proto_goTypes = []any{
	(*AzureResourceList)(nil),   // 0: accessgraph.v1alpha.AzureResourceList
	(*AzureResource)(nil),       // 1: accessgraph.v1alpha.AzureResource
	(*AzureVirtualMachine)(nil), // 2: accessgraph.v1alpha.AzureVirtualMachine
}
var file_accessgraph_v1alpha_azure_proto_depIdxs = []int32{
	1, // 0: accessgraph.v1alpha.AzureResourceList.resources:type_name -> accessgraph.v1alpha.AzureResource
	2, // 1: accessgraph.v1alpha.AzureResource.virtual_machine:type_name -> accessgraph.v1alpha.AzureVirtualMachine
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_accessgraph_v1alpha_azure_proto_init() }
func file_accessgraph_v1alpha_azure_proto_init() {
	if File_accessgraph_v1alpha_azure_proto != nil {
		return
	}
	file_accessgraph_v1alpha_azure_proto_msgTypes[1].OneofWrappers = []any{
		(*AzureResource_VirtualMachine)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_accessgraph_v1alpha_azure_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_accessgraph_v1alpha_azure_proto_goTypes,
		DependencyIndexes: file_accessgraph_v1alpha_azure_proto_depIdxs,
		MessageInfos:      file_accessgraph_v1alpha_azure_proto_msgTypes,
	}.Build()
	File_accessgraph_v1alpha_azure_proto = out.File
	file_accessgraph_v1alpha_azure_proto_rawDesc = nil
	file_accessgraph_v1alpha_azure_proto_goTypes = nil
	file_accessgraph_v1alpha_azure_proto_depIdxs = nil
}
