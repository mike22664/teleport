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

// @generated by protoc-gen-connect-query v1.4.2 with parameter "target=ts,import_extension=none,ts_nocheck=false"
// @generated from file teleport/machineid/v1/workload_identity_service.proto (package teleport.machineid.v1, syntax proto3)
/* eslint-disable */

import { MethodKind } from "@bufbuild/protobuf";
import { SignX509SVIDsRequest, SignX509SVIDsResponse } from "./workload_identity_service_pb";

/**
 * SignX509SVIDs generates signed x509 SVIDs based on the SVIDs provided in
 * the request.
 *
 * @generated from rpc teleport.machineid.v1.WorkloadIdentityService.SignX509SVIDs
 */
export const signX509SVIDs = {
  localName: "signX509SVIDs",
  name: "SignX509SVIDs",
  kind: MethodKind.Unary,
  I: SignX509SVIDsRequest,
  O: SignX509SVIDsResponse,
  service: {
    typeName: "teleport.machineid.v1.WorkloadIdentityService"
  }
} as const;
