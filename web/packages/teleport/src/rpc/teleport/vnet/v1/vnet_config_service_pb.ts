// Copyright 2024 Gravitational, Inc.
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

// @generated by protoc-gen-es v2.1.0 with parameter "target=ts"
// @generated from file teleport/vnet/v1/vnet_config_service.proto (package teleport.vnet.v1, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc, serviceDesc } from "@bufbuild/protobuf/codegenv1";
import type { EmptySchema } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_empty } from "@bufbuild/protobuf/wkt";
import type { VnetConfig, VnetConfigSchema } from "./vnet_config_pb";
import { file_teleport_vnet_v1_vnet_config } from "./vnet_config_pb";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file teleport/vnet/v1/vnet_config_service.proto.
 */
export const file_teleport_vnet_v1_vnet_config_service: GenFile = /*@__PURE__*/
  fileDesc("Cip0ZWxlcG9ydC92bmV0L3YxL3ZuZXRfY29uZmlnX3NlcnZpY2UucHJvdG8SEHRlbGVwb3J0LnZuZXQudjEiFgoUR2V0Vm5ldENvbmZpZ1JlcXVlc3QiTAoXQ3JlYXRlVm5ldENvbmZpZ1JlcXVlc3QSMQoLdm5ldF9jb25maWcYASABKAsyHC50ZWxlcG9ydC52bmV0LnYxLlZuZXRDb25maWciTAoXVXBkYXRlVm5ldENvbmZpZ1JlcXVlc3QSMQoLdm5ldF9jb25maWcYASABKAsyHC50ZWxlcG9ydC52bmV0LnYxLlZuZXRDb25maWciTAoXVXBzZXJ0Vm5ldENvbmZpZ1JlcXVlc3QSMQoLdm5ldF9jb25maWcYASABKAsyHC50ZWxlcG9ydC52bmV0LnYxLlZuZXRDb25maWciGQoXRGVsZXRlVm5ldENvbmZpZ1JlcXVlc3Qy2AMKEVZuZXRDb25maWdTZXJ2aWNlElUKDUdldFZuZXRDb25maWcSJi50ZWxlcG9ydC52bmV0LnYxLkdldFZuZXRDb25maWdSZXF1ZXN0GhwudGVsZXBvcnQudm5ldC52MS5WbmV0Q29uZmlnElsKEENyZWF0ZVZuZXRDb25maWcSKS50ZWxlcG9ydC52bmV0LnYxLkNyZWF0ZVZuZXRDb25maWdSZXF1ZXN0GhwudGVsZXBvcnQudm5ldC52MS5WbmV0Q29uZmlnElsKEFVwZGF0ZVZuZXRDb25maWcSKS50ZWxlcG9ydC52bmV0LnYxLlVwZGF0ZVZuZXRDb25maWdSZXF1ZXN0GhwudGVsZXBvcnQudm5ldC52MS5WbmV0Q29uZmlnElsKEFVwc2VydFZuZXRDb25maWcSKS50ZWxlcG9ydC52bmV0LnYxLlVwc2VydFZuZXRDb25maWdSZXF1ZXN0GhwudGVsZXBvcnQudm5ldC52MS5WbmV0Q29uZmlnElUKEERlbGV0ZVZuZXRDb25maWcSKS50ZWxlcG9ydC52bmV0LnYxLkRlbGV0ZVZuZXRDb25maWdSZXF1ZXN0GhYuZ29vZ2xlLnByb3RvYnVmLkVtcHR5QkpaSGdpdGh1Yi5jb20vZ3Jhdml0YXRpb25hbC90ZWxlcG9ydC9hcGkvZ2VuL3Byb3RvL2dvL3RlbGVwb3J0L3ZuZXQvdjE7dm5ldGIGcHJvdG8z", [file_google_protobuf_empty, file_teleport_vnet_v1_vnet_config]);

/**
 * Request for GetVnetConfig.
 *
 * @generated from message teleport.vnet.v1.GetVnetConfigRequest
 */
export type GetVnetConfigRequest = Message<"teleport.vnet.v1.GetVnetConfigRequest"> & {
};

/**
 * Describes the message teleport.vnet.v1.GetVnetConfigRequest.
 * Use `create(GetVnetConfigRequestSchema)` to create a new message.
 */
export const GetVnetConfigRequestSchema: GenMessage<GetVnetConfigRequest> = /*@__PURE__*/
  messageDesc(file_teleport_vnet_v1_vnet_config_service, 0);

/**
 * Request for CreateVnetConfig.
 *
 * @generated from message teleport.vnet.v1.CreateVnetConfigRequest
 */
export type CreateVnetConfigRequest = Message<"teleport.vnet.v1.CreateVnetConfigRequest"> & {
  /**
   * The VnetConfig resource to create.
   *
   * @generated from field: teleport.vnet.v1.VnetConfig vnet_config = 1;
   */
  vnetConfig?: VnetConfig;
};

/**
 * Describes the message teleport.vnet.v1.CreateVnetConfigRequest.
 * Use `create(CreateVnetConfigRequestSchema)` to create a new message.
 */
export const CreateVnetConfigRequestSchema: GenMessage<CreateVnetConfigRequest> = /*@__PURE__*/
  messageDesc(file_teleport_vnet_v1_vnet_config_service, 1);

/**
 * Request for UpdateVnetConfig.
 *
 * @generated from message teleport.vnet.v1.UpdateVnetConfigRequest
 */
export type UpdateVnetConfigRequest = Message<"teleport.vnet.v1.UpdateVnetConfigRequest"> & {
  /**
   * The VnetConfig resource to create.
   *
   * @generated from field: teleport.vnet.v1.VnetConfig vnet_config = 1;
   */
  vnetConfig?: VnetConfig;
};

/**
 * Describes the message teleport.vnet.v1.UpdateVnetConfigRequest.
 * Use `create(UpdateVnetConfigRequestSchema)` to create a new message.
 */
export const UpdateVnetConfigRequestSchema: GenMessage<UpdateVnetConfigRequest> = /*@__PURE__*/
  messageDesc(file_teleport_vnet_v1_vnet_config_service, 2);

/**
 * Request for UpsertVnetConfig.
 *
 * @generated from message teleport.vnet.v1.UpsertVnetConfigRequest
 */
export type UpsertVnetConfigRequest = Message<"teleport.vnet.v1.UpsertVnetConfigRequest"> & {
  /**
   * The VnetConfig resource to create.
   *
   * @generated from field: teleport.vnet.v1.VnetConfig vnet_config = 1;
   */
  vnetConfig?: VnetConfig;
};

/**
 * Describes the message teleport.vnet.v1.UpsertVnetConfigRequest.
 * Use `create(UpsertVnetConfigRequestSchema)` to create a new message.
 */
export const UpsertVnetConfigRequestSchema: GenMessage<UpsertVnetConfigRequest> = /*@__PURE__*/
  messageDesc(file_teleport_vnet_v1_vnet_config_service, 3);

/**
 * Request for DeleteVnetConfig.
 *
 * @generated from message teleport.vnet.v1.DeleteVnetConfigRequest
 */
export type DeleteVnetConfigRequest = Message<"teleport.vnet.v1.DeleteVnetConfigRequest"> & {
};

/**
 * Describes the message teleport.vnet.v1.DeleteVnetConfigRequest.
 * Use `create(DeleteVnetConfigRequestSchema)` to create a new message.
 */
export const DeleteVnetConfigRequestSchema: GenMessage<DeleteVnetConfigRequest> = /*@__PURE__*/
  messageDesc(file_teleport_vnet_v1_vnet_config_service, 4);

/**
 * VnetConfigService provides an API to manage the singleton VnetConfig.
 *
 * @generated from service teleport.vnet.v1.VnetConfigService
 */
export const VnetConfigService: GenService<{
  /**
   * GetVnetConfig returns the specified VnetConfig.
   *
   * @generated from rpc teleport.vnet.v1.VnetConfigService.GetVnetConfig
   */
  getVnetConfig: {
    methodKind: "unary";
    input: typeof GetVnetConfigRequestSchema;
    output: typeof VnetConfigSchema;
  },
  /**
   * CreateVnetConfig creates a new VnetConfig.
   *
   * @generated from rpc teleport.vnet.v1.VnetConfigService.CreateVnetConfig
   */
  createVnetConfig: {
    methodKind: "unary";
    input: typeof CreateVnetConfigRequestSchema;
    output: typeof VnetConfigSchema;
  },
  /**
   * UpdateVnetConfig updates an existing VnetConfig.
   *
   * @generated from rpc teleport.vnet.v1.VnetConfigService.UpdateVnetConfig
   */
  updateVnetConfig: {
    methodKind: "unary";
    input: typeof UpdateVnetConfigRequestSchema;
    output: typeof VnetConfigSchema;
  },
  /**
   * UpsertVnetConfig creates a new VnetConfig or replaces an existing VnetConfig.
   *
   * @generated from rpc teleport.vnet.v1.VnetConfigService.UpsertVnetConfig
   */
  upsertVnetConfig: {
    methodKind: "unary";
    input: typeof UpsertVnetConfigRequestSchema;
    output: typeof VnetConfigSchema;
  },
  /**
   * DeleteVnetConfig hard deletes the specified VnetConfig.
   *
   * @generated from rpc teleport.vnet.v1.VnetConfigService.DeleteVnetConfig
   */
  deleteVnetConfig: {
    methodKind: "unary";
    input: typeof DeleteVnetConfigRequestSchema;
    output: typeof EmptySchema;
  },
}> = /*@__PURE__*/
  serviceDesc(file_teleport_vnet_v1_vnet_config_service, 0);

