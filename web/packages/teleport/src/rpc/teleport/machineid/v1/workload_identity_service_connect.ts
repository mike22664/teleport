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

// @generated by protoc-gen-connect-es v1.5.0 with parameter "target=ts"
// @generated from file teleport/machineid/v1/workload_identity_service.proto (package teleport.machineid.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { SignX509SVIDsRequest, SignX509SVIDsResponse } from "./workload_identity_service_pb.js";
import { MethodKind } from "@bufbuild/protobuf";

/**
 * WorkloadIdentityService provides the signing of workload identity documents.
 * It currently only supports signing SPIFFE x509 SVIDs.
 *
 * @generated from service teleport.machineid.v1.WorkloadIdentityService
 */
export const WorkloadIdentityService = {
  typeName: "teleport.machineid.v1.WorkloadIdentityService",
  methods: {
    /**
     * SignX509SVIDs generates signed x509 SVIDs based on the SVIDs provided in
     * the request.
     *
     * @generated from rpc teleport.machineid.v1.WorkloadIdentityService.SignX509SVIDs
     */
    signX509SVIDs: {
      name: "SignX509SVIDs",
      I: SignX509SVIDsRequest,
      O: SignX509SVIDsResponse,
      kind: MethodKind.Unary,
    },
  }
} as const;

