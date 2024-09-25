// Copyright 2021-2022 Gravitational, Inc
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
// @generated from file teleport/samlidp/v1/samlidp.proto (package teleport.samlidp.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { ProcessSAMLIdPRequestRequest, ProcessSAMLIdPRequestResponse, TestSAMLIdPAttributeMappingRequest, TestSAMLIdPAttributeMappingResponse } from "./samlidp_pb.js";
import { MethodKind } from "@bufbuild/protobuf";

/**
 * SAMLIdPService provides utility methods for the SAML identity provider.
 *
 * @generated from service teleport.samlidp.v1.SAMLIdPService
 */
export const SAMLIdPService = {
  typeName: "teleport.samlidp.v1.SAMLIdPService",
  methods: {
    /**
     * ProcessSAMLIdPRequest processes the SAML auth request.
     *
     * @generated from rpc teleport.samlidp.v1.SAMLIdPService.ProcessSAMLIdPRequest
     */
    processSAMLIdPRequest: {
      name: "ProcessSAMLIdPRequest",
      I: ProcessSAMLIdPRequestRequest,
      O: ProcessSAMLIdPRequestResponse,
      kind: MethodKind.Unary,
    },
    /**
     * TestSAMLIdPAttributeMapping tests SAML attribute mapping configuration.
     *
     * @generated from rpc teleport.samlidp.v1.SAMLIdPService.TestSAMLIdPAttributeMapping
     */
    testSAMLIdPAttributeMapping: {
      name: "TestSAMLIdPAttributeMapping",
      I: TestSAMLIdPAttributeMappingRequest,
      O: TestSAMLIdPAttributeMappingResponse,
      kind: MethodKind.Unary,
    },
  }
} as const;

