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

// @generated by protoc-gen-es v2.1.0 with parameter "target=ts"
// @generated from file teleport/machineid/v1/workload_identity_service.proto (package teleport.machineid.v1, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc, serviceDesc } from "@bufbuild/protobuf/codegenv1";
import type { Duration } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_duration } from "@bufbuild/protobuf/wkt";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file teleport/machineid/v1/workload_identity_service.proto.
 */
export const file_teleport_machineid_v1_workload_identity_service: GenFile = /*@__PURE__*/
  fileDesc("CjV0ZWxlcG9ydC9tYWNoaW5laWQvdjEvd29ya2xvYWRfaWRlbnRpdHlfc2VydmljZS5wcm90bxIVdGVsZXBvcnQubWFjaGluZWlkLnYxIpIBCgtTVklEUmVxdWVzdBISCgpwdWJsaWNfa2V5GAEgASgMEhYKDnNwaWZmZV9pZF9wYXRoGAIgASgJEhAKCGRuc19zYW5zGAMgAygJEg8KB2lwX3NhbnMYBCADKAkSDAoEaGludBgFIAEoCRImCgN0dGwYBiABKAsyGS5nb29nbGUucHJvdG9idWYuRHVyYXRpb24iRAoMU1ZJRFJlc3BvbnNlEhMKC2NlcnRpZmljYXRlGAEgASgMEhEKCXNwaWZmZV9pZBgCIAEoCRIMCgRoaW50GAMgASgJIkkKFFNpZ25YNTA5U1ZJRHNSZXF1ZXN0EjEKBXN2aWRzGAEgAygLMiIudGVsZXBvcnQubWFjaGluZWlkLnYxLlNWSURSZXF1ZXN0IksKFVNpZ25YNTA5U1ZJRHNSZXNwb25zZRIyCgVzdmlkcxgBIAMoCzIjLnRlbGVwb3J0Lm1hY2hpbmVpZC52MS5TVklEUmVzcG9uc2UyhwEKF1dvcmtsb2FkSWRlbnRpdHlTZXJ2aWNlEmwKDVNpZ25YNTA5U1ZJRHMSKy50ZWxlcG9ydC5tYWNoaW5laWQudjEuU2lnblg1MDlTVklEc1JlcXVlc3QaLC50ZWxlcG9ydC5tYWNoaW5laWQudjEuU2lnblg1MDlTVklEc1Jlc3BvbnNlIgBCVlpUZ2l0aHViLmNvbS9ncmF2aXRhdGlvbmFsL3RlbGVwb3J0L2FwaS9nZW4vcHJvdG8vZ28vdGVsZXBvcnQvbWFjaGluZWlkL3YxO21hY2hpbmVpZHYxYgZwcm90bzM", [file_google_protobuf_duration]);

/**
 * The request for an individual x509 SVID.
 *
 * @generated from message teleport.machineid.v1.SVIDRequest
 */
export type SVIDRequest = Message<"teleport.machineid.v1.SVIDRequest"> & {
  /**
   * A PKIX, ASN.1 DER encoded public key that should be included in the x509
   * SVID.
   * Required.
   *
   * @generated from field: bytes public_key = 1;
   */
  publicKey: Uint8Array;

  /**
   * The path that should be included in the SPIFFE ID.
   * This should have a preceding slash and should not have a trailing slash.
   * Required.
   *
   * @generated from field: string spiffe_id_path = 2;
   */
  spiffeIdPath: string;

  /**
   * The DNS SANs that should be included in the x509 SVID.
   * Optional.
   *
   * @generated from field: repeated string dns_sans = 3;
   */
  dnsSans: string[];

  /**
   * The IP SANs that should be included in the x509 SVID.
   * Optional.
   *
   * @generated from field: repeated string ip_sans = 4;
   */
  ipSans: string[];

  /**
   * A hint that provides a way of distinguishing between SVIDs. These are
   * user configured and are sent back to the actual workload.
   * Optional.
   *
   * @generated from field: string hint = 5;
   */
  hint: string;

  /**
   * The TTL to use for the x509 SVID. A maximum value is enforced on this
   * field. Callers should inspect the returned cert to determine if their
   * requested TTL has been met, and if not, adjust their behaviour. If not
   * supplied, the default TTL will be the maximum value.
   *
   * @generated from field: google.protobuf.Duration ttl = 6;
   */
  ttl?: Duration;
};

/**
 * Describes the message teleport.machineid.v1.SVIDRequest.
 * Use `create(SVIDRequestSchema)` to create a new message.
 */
export const SVIDRequestSchema: GenMessage<SVIDRequest> = /*@__PURE__*/
  messageDesc(file_teleport_machineid_v1_workload_identity_service, 0);

/**
 * The generated x509 SVID.
 *
 * @generated from message teleport.machineid.v1.SVIDResponse
 */
export type SVIDResponse = Message<"teleport.machineid.v1.SVIDResponse"> & {
  /**
   * A ASN.1 DER encoded x509 SVID.
   *
   * @generated from field: bytes certificate = 1;
   */
  certificate: Uint8Array;

  /**
   * The full SPIFFE ID that was included in the x509 SVID.
   *
   * @generated from field: string spiffe_id = 2;
   */
  spiffeId: string;

  /**
   * The hint that was included in SVIDRequest in order to allow a workload to
   * distinguish an individual SVID.
   *
   * @generated from field: string hint = 3;
   */
  hint: string;
};

/**
 * Describes the message teleport.machineid.v1.SVIDResponse.
 * Use `create(SVIDResponseSchema)` to create a new message.
 */
export const SVIDResponseSchema: GenMessage<SVIDResponse> = /*@__PURE__*/
  messageDesc(file_teleport_machineid_v1_workload_identity_service, 1);

/**
 * The request for SignX509SVIDs.
 *
 * @generated from message teleport.machineid.v1.SignX509SVIDsRequest
 */
export type SignX509SVIDsRequest = Message<"teleport.machineid.v1.SignX509SVIDsRequest"> & {
  /**
   * The SVIDs that should be generated. This is repeated to allow a bot to
   * request multiple SVIDs at once and reduce the number of round trips.
   * Must be non-zero length.
   *
   * @generated from field: repeated teleport.machineid.v1.SVIDRequest svids = 1;
   */
  svids: SVIDRequest[];
};

/**
 * Describes the message teleport.machineid.v1.SignX509SVIDsRequest.
 * Use `create(SignX509SVIDsRequestSchema)` to create a new message.
 */
export const SignX509SVIDsRequestSchema: GenMessage<SignX509SVIDsRequest> = /*@__PURE__*/
  messageDesc(file_teleport_machineid_v1_workload_identity_service, 2);

/**
 * The response for SignX509SVIDs.
 *
 * @generated from message teleport.machineid.v1.SignX509SVIDsResponse
 */
export type SignX509SVIDsResponse = Message<"teleport.machineid.v1.SignX509SVIDsResponse"> & {
  /**
   * The generated SVIDs.
   *
   * @generated from field: repeated teleport.machineid.v1.SVIDResponse svids = 1;
   */
  svids: SVIDResponse[];
};

/**
 * Describes the message teleport.machineid.v1.SignX509SVIDsResponse.
 * Use `create(SignX509SVIDsResponseSchema)` to create a new message.
 */
export const SignX509SVIDsResponseSchema: GenMessage<SignX509SVIDsResponse> = /*@__PURE__*/
  messageDesc(file_teleport_machineid_v1_workload_identity_service, 3);

/**
 * WorkloadIdentityService provides the signing of workload identity documents.
 * It currently only supports signing SPIFFE x509 SVIDs.
 *
 * @generated from service teleport.machineid.v1.WorkloadIdentityService
 */
export const WorkloadIdentityService: GenService<{
  /**
   * SignX509SVIDs generates signed x509 SVIDs based on the SVIDs provided in
   * the request.
   *
   * @generated from rpc teleport.machineid.v1.WorkloadIdentityService.SignX509SVIDs
   */
  signX509SVIDs: {
    methodKind: "unary";
    input: typeof SignX509SVIDsRequestSchema;
    output: typeof SignX509SVIDsResponseSchema;
  },
}> = /*@__PURE__*/
  serviceDesc(file_teleport_machineid_v1_workload_identity_service, 0);

