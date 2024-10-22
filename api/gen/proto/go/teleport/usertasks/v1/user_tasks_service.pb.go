// Copyright 2024 Gravitational, Inc
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
// 	protoc-gen-go v1.34.0
// 	protoc        (unknown)
// source: teleport/usertasks/v1/user_tasks_service.proto

package usertasksv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// CreateUserTaskRequest is a request to create a User Task.
type CreateUserTaskRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserTask *UserTask `protobuf:"bytes,1,opt,name=user_task,json=userTask,proto3" json:"user_task,omitempty"`
}

func (x *CreateUserTaskRequest) Reset() {
	*x = CreateUserTaskRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateUserTaskRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateUserTaskRequest) ProtoMessage() {}

func (x *CreateUserTaskRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateUserTaskRequest.ProtoReflect.Descriptor instead.
func (*CreateUserTaskRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{0}
}

func (x *CreateUserTaskRequest) GetUserTask() *UserTask {
	if x != nil {
		return x.UserTask
	}
	return nil
}

// UpsertUserTaskRequest is a request to create or update a User Task.
type UpsertUserTaskRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserTask *UserTask `protobuf:"bytes,1,opt,name=user_task,json=userTask,proto3" json:"user_task,omitempty"`
}

func (x *UpsertUserTaskRequest) Reset() {
	*x = UpsertUserTaskRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertUserTaskRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertUserTaskRequest) ProtoMessage() {}

func (x *UpsertUserTaskRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertUserTaskRequest.ProtoReflect.Descriptor instead.
func (*UpsertUserTaskRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{1}
}

func (x *UpsertUserTaskRequest) GetUserTask() *UserTask {
	if x != nil {
		return x.UserTask
	}
	return nil
}

// GetUserTaskRequest is a request to get a User Task by name.
type GetUserTaskRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the UserTask to get.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetUserTaskRequest) Reset() {
	*x = GetUserTaskRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserTaskRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserTaskRequest) ProtoMessage() {}

func (x *GetUserTaskRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserTaskRequest.ProtoReflect.Descriptor instead.
func (*GetUserTaskRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetUserTaskRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// ListUserTasksRequest is a request to get a list of User Tasks.
type ListUserTasksRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// page_size is the maximum number of items to return.
	// The server may impose a different page size at its discretion.
	PageSize int64 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// page_token is the next_page_token value returned from a previous List request, if any.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListUserTasksRequest) Reset() {
	*x = ListUserTasksRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListUserTasksRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUserTasksRequest) ProtoMessage() {}

func (x *ListUserTasksRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUserTasksRequest.ProtoReflect.Descriptor instead.
func (*ListUserTasksRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListUserTasksRequest) GetPageSize() int64 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListUserTasksRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListUserTasksByIntegrationRequest is a request to get a list of User Tasks filtered by an Integration.
type ListUserTasksByIntegrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// page_size is the maximum number of items to return.
	// The server may impose a different page size at its discretion.
	PageSize int64 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// page_token is the next_page_token value returned from a previous List request, if any.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
	// integration is the integration name that will be used to filter the returned list.
	Integration string `protobuf:"bytes,3,opt,name=integration,proto3" json:"integration,omitempty"`
}

func (x *ListUserTasksByIntegrationRequest) Reset() {
	*x = ListUserTasksByIntegrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListUserTasksByIntegrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUserTasksByIntegrationRequest) ProtoMessage() {}

func (x *ListUserTasksByIntegrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUserTasksByIntegrationRequest.ProtoReflect.Descriptor instead.
func (*ListUserTasksByIntegrationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{4}
}

func (x *ListUserTasksByIntegrationRequest) GetPageSize() int64 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListUserTasksByIntegrationRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

func (x *ListUserTasksByIntegrationRequest) GetIntegration() string {
	if x != nil {
		return x.Integration
	}
	return ""
}

// ListUserTasksResponse is a response to ListUserTasks.
type ListUserTasksResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserTasks []*UserTask `protobuf:"bytes,1,rep,name=user_tasks,json=userTasks,proto3" json:"user_tasks,omitempty"`
	// Token to retrieve the next page of results, or empty if there are no
	// more results in the list.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *ListUserTasksResponse) Reset() {
	*x = ListUserTasksResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListUserTasksResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUserTasksResponse) ProtoMessage() {}

func (x *ListUserTasksResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUserTasksResponse.ProtoReflect.Descriptor instead.
func (*ListUserTasksResponse) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{5}
}

func (x *ListUserTasksResponse) GetUserTasks() []*UserTask {
	if x != nil {
		return x.UserTasks
	}
	return nil
}

func (x *ListUserTasksResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

// UpdateUserTaskRequest is a request to update an existing User Task.
type UpdateUserTaskRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserTask *UserTask `protobuf:"bytes,1,opt,name=user_task,json=userTask,proto3" json:"user_task,omitempty"`
}

func (x *UpdateUserTaskRequest) Reset() {
	*x = UpdateUserTaskRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateUserTaskRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateUserTaskRequest) ProtoMessage() {}

func (x *UpdateUserTaskRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateUserTaskRequest.ProtoReflect.Descriptor instead.
func (*UpdateUserTaskRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{6}
}

func (x *UpdateUserTaskRequest) GetUserTask() *UserTask {
	if x != nil {
		return x.UserTask
	}
	return nil
}

// DeleteUserTaskRequest is a request to delete a User Task.
type DeleteUserTaskRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the User Task to delete.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteUserTaskRequest) Reset() {
	*x = DeleteUserTaskRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserTaskRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserTaskRequest) ProtoMessage() {}

func (x *DeleteUserTaskRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserTaskRequest.ProtoReflect.Descriptor instead.
func (*DeleteUserTaskRequest) Descriptor() ([]byte, []int) {
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP(), []int{7}
}

func (x *DeleteUserTaskRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_teleport_usertasks_v1_user_tasks_service_proto protoreflect.FileDescriptor

var file_teleport_usertasks_v1_user_tasks_service_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x74,
	0x61, 0x73, 0x6b, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x74, 0x61, 0x73,
	0x6b, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x15, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74,
	0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x26, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75,
	0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x73, 0x65, 0x72,
	0x5f, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x55, 0x0a, 0x15,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3c, 0x0a, 0x09, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x74, 0x61,
	0x73, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x54,
	0x61, 0x73, 0x6b, 0x22, 0x55, 0x0a, 0x15, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x55, 0x73, 0x65,
	0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3c, 0x0a, 0x09,
	0x75, 0x73, 0x65, 0x72, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74,
	0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b,
	0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x22, 0x28, 0x0a, 0x12, 0x47, 0x65,
	0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x52, 0x0a, 0x14, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72,
	0x54, 0x61, 0x73, 0x6b, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09,
	0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x67,
	0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70,
	0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x81, 0x01, 0x0a, 0x21, 0x4c, 0x69, 0x73,
	0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x42, 0x79, 0x49, 0x6e, 0x74, 0x65,
	0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b,
	0x0a, 0x09, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70,
	0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x70, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x69, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x7f, 0x0a, 0x15,
	0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3e, 0x0a, 0x0a, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x74, 0x61,
	0x73, 0x6b, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x09, 0x75, 0x73, 0x65, 0x72,
	0x54, 0x61, 0x73, 0x6b, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x70, 0x61,
	0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d,
	0x6e, 0x65, 0x78, 0x74, 0x50, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x55, 0x0a,
	0x15, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3c, 0x0a, 0x09, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x74,
	0x61, 0x73, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x54, 0x61, 0x73, 0x6b, 0x22, 0x2b, 0x0a, 0x15, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73,
	0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x32, 0xda, 0x05, 0x0a, 0x0f, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5f, 0x0a, 0x0e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x55,
	0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73,
	0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x5f, 0x0a, 0x0e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74,
	0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55,
	0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x59, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x55, 0x73,
	0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x29, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65,
	0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61,
	0x73, 0x6b, 0x12, 0x6a, 0x0a, 0x0d, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61,
	0x73, 0x6b, 0x73, 0x12, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75,
	0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74,
	0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72,
	0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65,
	0x72, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x84,
	0x01, 0x0a, 0x1a, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x73,
	0x42, 0x79, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73,
	0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61,
	0x73, 0x6b, 0x73, 0x42, 0x79, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5f, 0x0a, 0x0e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x55,
	0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73,
	0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x56, 0x0a, 0x0e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x56,
	0x5a, 0x54, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61,
	0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x73,
	0x65, 0x72, 0x74, 0x61, 0x73, 0x6b, 0x73, 0x2f, 0x76, 0x31, 0x3b, 0x75, 0x73, 0x65, 0x72, 0x74,
	0x61, 0x73, 0x6b, 0x73, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_usertasks_v1_user_tasks_service_proto_rawDescOnce sync.Once
	file_teleport_usertasks_v1_user_tasks_service_proto_rawDescData = file_teleport_usertasks_v1_user_tasks_service_proto_rawDesc
)

func file_teleport_usertasks_v1_user_tasks_service_proto_rawDescGZIP() []byte {
	file_teleport_usertasks_v1_user_tasks_service_proto_rawDescOnce.Do(func() {
		file_teleport_usertasks_v1_user_tasks_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_usertasks_v1_user_tasks_service_proto_rawDescData)
	})
	return file_teleport_usertasks_v1_user_tasks_service_proto_rawDescData
}

var file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_teleport_usertasks_v1_user_tasks_service_proto_goTypes = []interface{}{
	(*CreateUserTaskRequest)(nil),             // 0: teleport.usertasks.v1.CreateUserTaskRequest
	(*UpsertUserTaskRequest)(nil),             // 1: teleport.usertasks.v1.UpsertUserTaskRequest
	(*GetUserTaskRequest)(nil),                // 2: teleport.usertasks.v1.GetUserTaskRequest
	(*ListUserTasksRequest)(nil),              // 3: teleport.usertasks.v1.ListUserTasksRequest
	(*ListUserTasksByIntegrationRequest)(nil), // 4: teleport.usertasks.v1.ListUserTasksByIntegrationRequest
	(*ListUserTasksResponse)(nil),             // 5: teleport.usertasks.v1.ListUserTasksResponse
	(*UpdateUserTaskRequest)(nil),             // 6: teleport.usertasks.v1.UpdateUserTaskRequest
	(*DeleteUserTaskRequest)(nil),             // 7: teleport.usertasks.v1.DeleteUserTaskRequest
	(*UserTask)(nil),                          // 8: teleport.usertasks.v1.UserTask
	(*emptypb.Empty)(nil),                     // 9: google.protobuf.Empty
}
var file_teleport_usertasks_v1_user_tasks_service_proto_depIdxs = []int32{
	8,  // 0: teleport.usertasks.v1.CreateUserTaskRequest.user_task:type_name -> teleport.usertasks.v1.UserTask
	8,  // 1: teleport.usertasks.v1.UpsertUserTaskRequest.user_task:type_name -> teleport.usertasks.v1.UserTask
	8,  // 2: teleport.usertasks.v1.ListUserTasksResponse.user_tasks:type_name -> teleport.usertasks.v1.UserTask
	8,  // 3: teleport.usertasks.v1.UpdateUserTaskRequest.user_task:type_name -> teleport.usertasks.v1.UserTask
	0,  // 4: teleport.usertasks.v1.UserTaskService.CreateUserTask:input_type -> teleport.usertasks.v1.CreateUserTaskRequest
	1,  // 5: teleport.usertasks.v1.UserTaskService.UpsertUserTask:input_type -> teleport.usertasks.v1.UpsertUserTaskRequest
	2,  // 6: teleport.usertasks.v1.UserTaskService.GetUserTask:input_type -> teleport.usertasks.v1.GetUserTaskRequest
	3,  // 7: teleport.usertasks.v1.UserTaskService.ListUserTasks:input_type -> teleport.usertasks.v1.ListUserTasksRequest
	4,  // 8: teleport.usertasks.v1.UserTaskService.ListUserTasksByIntegration:input_type -> teleport.usertasks.v1.ListUserTasksByIntegrationRequest
	6,  // 9: teleport.usertasks.v1.UserTaskService.UpdateUserTask:input_type -> teleport.usertasks.v1.UpdateUserTaskRequest
	7,  // 10: teleport.usertasks.v1.UserTaskService.DeleteUserTask:input_type -> teleport.usertasks.v1.DeleteUserTaskRequest
	8,  // 11: teleport.usertasks.v1.UserTaskService.CreateUserTask:output_type -> teleport.usertasks.v1.UserTask
	8,  // 12: teleport.usertasks.v1.UserTaskService.UpsertUserTask:output_type -> teleport.usertasks.v1.UserTask
	8,  // 13: teleport.usertasks.v1.UserTaskService.GetUserTask:output_type -> teleport.usertasks.v1.UserTask
	5,  // 14: teleport.usertasks.v1.UserTaskService.ListUserTasks:output_type -> teleport.usertasks.v1.ListUserTasksResponse
	5,  // 15: teleport.usertasks.v1.UserTaskService.ListUserTasksByIntegration:output_type -> teleport.usertasks.v1.ListUserTasksResponse
	8,  // 16: teleport.usertasks.v1.UserTaskService.UpdateUserTask:output_type -> teleport.usertasks.v1.UserTask
	9,  // 17: teleport.usertasks.v1.UserTaskService.DeleteUserTask:output_type -> google.protobuf.Empty
	11, // [11:18] is the sub-list for method output_type
	4,  // [4:11] is the sub-list for method input_type
	4,  // [4:4] is the sub-list for extension type_name
	4,  // [4:4] is the sub-list for extension extendee
	0,  // [0:4] is the sub-list for field type_name
}

func init() { file_teleport_usertasks_v1_user_tasks_service_proto_init() }
func file_teleport_usertasks_v1_user_tasks_service_proto_init() {
	if File_teleport_usertasks_v1_user_tasks_service_proto != nil {
		return
	}
	file_teleport_usertasks_v1_user_tasks_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateUserTaskRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertUserTaskRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUserTaskRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListUserTasksRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListUserTasksByIntegrationRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListUserTasksResponse); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateUserTaskRequest); i {
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
		file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteUserTaskRequest); i {
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
			RawDescriptor: file_teleport_usertasks_v1_user_tasks_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_usertasks_v1_user_tasks_service_proto_goTypes,
		DependencyIndexes: file_teleport_usertasks_v1_user_tasks_service_proto_depIdxs,
		MessageInfos:      file_teleport_usertasks_v1_user_tasks_service_proto_msgTypes,
	}.Build()
	File_teleport_usertasks_v1_user_tasks_service_proto = out.File
	file_teleport_usertasks_v1_user_tasks_service_proto_rawDesc = nil
	file_teleport_usertasks_v1_user_tasks_service_proto_goTypes = nil
	file_teleport_usertasks_v1_user_tasks_service_proto_depIdxs = nil
}
