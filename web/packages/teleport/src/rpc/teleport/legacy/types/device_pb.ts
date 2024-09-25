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
// @generated from file teleport/legacy/types/device.proto (package types, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv1";
import { file_gogoproto_gogo } from "../../../gogoproto/gogo_pb";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_timestamp } from "@bufbuild/protobuf/wkt";
import type { ResourceHeader } from "./types_pb";
import { file_teleport_legacy_types_types } from "./types_pb";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file teleport/legacy/types/device.proto.
 */
export const file_teleport_legacy_types_device: GenFile = /*@__PURE__*/
  fileDesc("CiJ0ZWxlcG9ydC9sZWdhY3kvdHlwZXMvZGV2aWNlLnByb3RvEgV0eXBlcyJqCghEZXZpY2VWMRIzCgZIZWFkZXIYASABKAsyFS50eXBlcy5SZXNvdXJjZUhlYWRlckIMyN4fANDeHwHq3h8AEikKBHNwZWMYBSABKAsyES50eXBlcy5EZXZpY2VTcGVjQgjq3h8Ec3BlYyK4BAoKRGV2aWNlU3BlYxIcCgdvc190eXBlGAEgASgJQgvq3h8Hb3NfdHlwZRIgCglhc3NldF90YWcYAiABKAlCDereHwlhc3NldF90YWcSRAoLY3JlYXRlX3RpbWUYAyABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wQhPq3h8LY3JlYXRlX3RpbWWQ3x8BEkQKC3VwZGF0ZV90aW1lGAQgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcEIT6t4fC3VwZGF0ZV90aW1lkN8fARIoCg1lbnJvbGxfc3RhdHVzGAUgASgJQhHq3h8NZW5yb2xsX3N0YXR1cxJFCgpjcmVkZW50aWFsGAYgASgLMhcudHlwZXMuRGV2aWNlQ3JlZGVudGlhbEIY6t4fFGNyZWRlbnRpYWwsb21pdGVtcHR5ElAKDmNvbGxlY3RlZF9kYXRhGAcgAygLMhoudHlwZXMuRGV2aWNlQ29sbGVjdGVkRGF0YUIc6t4fGGNvbGxlY3RlZF9kYXRhLG9taXRlbXB0eRI5CgZzb3VyY2UYCCABKAsyEy50eXBlcy5EZXZpY2VTb3VyY2VCFOreHxBzb3VyY2Usb21pdGVtcHR5EjwKB3Byb2ZpbGUYCSABKAsyFC50eXBlcy5EZXZpY2VQcm9maWxlQhXq3h8RcHJvZmlsZSxvbWl0ZW1wdHkSIgoFb3duZXIYCiABKAlCE+reHw9vd25lcixvbWl0ZW1wdHkilAIKEERldmljZUNyZWRlbnRpYWwSEgoCaWQYASABKAlCBureHwJpZBI0Cg5wdWJsaWNfa2V5X2RlchgCIAEoDEIc6t4fGHB1YmxpY19rZXlfZGVyLG9taXRlbXB0eRJGChdkZXZpY2VfYXR0ZXN0YXRpb25fdHlwZRgDIAEoCUIl6t4fIWRldmljZV9hdHRlc3RhdGlvbl90eXBlLG9taXRlbXB0eRI6ChF0cG1fZWtjZXJ0X3NlcmlhbBgEIAEoCUIf6t4fG3RwbV9la2NlcnRfc2VyaWFsLG9taXRlbXB0eRIyCg10cG1fYWtfcHVibGljGAUgASgMQhvq3h8XdHBtX2FrX3B1YmxpYyxvbWl0ZW1wdHkimgcKE0RldmljZUNvbGxlY3RlZERhdGESRgoMY29sbGVjdF90aW1lGAEgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcEIU6t4fDGNvbGxlY3RfdGltZZDfHwESRAoLcmVjb3JkX3RpbWUYAiABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wQhPq3h8LcmVjb3JkX3RpbWWQ3x8BEhwKB29zX3R5cGUYAyABKAlCC+reHwdvc190eXBlEjIKDXNlcmlhbF9udW1iZXIYBCABKAlCG+reHxdzZXJpYWxfbnVtYmVyLG9taXRlbXB0eRI4ChBtb2RlbF9pZGVudGlmaWVyGAUgASgJQh7q3h8abW9kZWxfaWRlbnRpZmllcixvbWl0ZW1wdHkSLAoKb3NfdmVyc2lvbhgGIAEoCUIY6t4fFG9zX3ZlcnNpb24sb21pdGVtcHR5EigKCG9zX2J1aWxkGAcgASgJQhbq3h8Sb3NfYnVpbGQsb21pdGVtcHR5Ei4KC29zX3VzZXJuYW1lGAggASgJQhnq3h8Vb3NfdXNlcm5hbWUsb21pdGVtcHR5Ej4KE2phbWZfYmluYXJ5X3ZlcnNpb24YCSABKAlCIereHx1qYW1mX2JpbmFyeV92ZXJzaW9uLG9taXRlbXB0eRJKChltYWNvc19lbnJvbGxtZW50X3Byb2ZpbGVzGAogASgJQifq3h8jbWFjb3NfZW5yb2xsbWVudF9wcm9maWxlcyxvbWl0ZW1wdHkSPAoScmVwb3J0ZWRfYXNzZXRfdGFnGAsgASgJQiDq3h8ccmVwb3J0ZWRfYXNzZXRfdGFnLG9taXRlbXB0eRJAChRzeXN0ZW1fc2VyaWFsX251bWJlchgMIAEoCUIi6t4fHnN5c3RlbV9zZXJpYWxfbnVtYmVyLG9taXRlbXB0eRJIChhiYXNlX2JvYXJkX3NlcmlhbF9udW1iZXIYDSABKAlCJureHyJiYXNlX2JvYXJkX3NlcmlhbF9udW1iZXIsb21pdGVtcHR5EmcKGHRwbV9wbGF0Zm9ybV9hdHRlc3RhdGlvbhgOIAEoCzIdLnR5cGVzLlRQTVBsYXRmb3JtQXR0ZXN0YXRpb25CJureHyJ0cG1fcGxhdGZvcm1fYXR0ZXN0YXRpb24sb21pdGVtcHR5EiIKBW9zX2lkGA8gASgJQhPq3h8Pb3NfaWQsb21pdGVtcHR5ImIKBlRQTVBDUhIYCgVpbmRleBgBIAEoBUIJ6t4fBWluZGV4EhoKBmRpZ2VzdBgCIAEoDEIK6t4fBmRpZ2VzdBIiCgpkaWdlc3RfYWxnGAMgASgEQg7q3h8KZGlnZXN0X2FsZyJGCghUUE1RdW90ZRIYCgVxdW90ZRgBIAEoDEIJ6t4fBXF1b3RlEiAKCXNpZ25hdHVyZRgCIAEoDEIN6t4fCXNpZ25hdHVyZSKNAQoVVFBNUGxhdGZvcm1QYXJhbWV0ZXJzEisKBnF1b3RlcxgBIAMoCzIPLnR5cGVzLlRQTVF1b3RlQgrq3h8GcXVvdGVzEiUKBHBjcnMYAiADKAsyDS50eXBlcy5UUE1QQ1JCCOreHwRwY3JzEiAKCWV2ZW50X2xvZxgDIAEoDEIN6t4fCWV2ZW50X2xvZyKaAQoWVFBNUGxhdGZvcm1BdHRlc3RhdGlvbhIiCgVub25jZRgBIAEoDEIT6t4fD25vbmNlLG9taXRlbXB0eRJcChNwbGF0Zm9ybV9wYXJhbWV0ZXJzGAIgASgLMhwudHlwZXMuVFBNUGxhdGZvcm1QYXJhbWV0ZXJzQiHq3h8dcGxhdGZvcm1fcGFyYW1ldGVycyxvbWl0ZW1wdHkiQgoMRGV2aWNlU291cmNlEhYKBG5hbWUYASABKAlCCOreHwRuYW1lEhoKBm9yaWdpbhgCIAEoCUIK6t4fBm9yaWdpbiL7AwoNRGV2aWNlUHJvZmlsZRJOCgt1cGRhdGVfdGltZRgBIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBCHereHxV1cGRhdGVfdGltZSxvbWl0ZW1wdHmQ3x8BEjgKEG1vZGVsX2lkZW50aWZpZXIYAiABKAlCHureHxptb2RlbF9pZGVudGlmaWVyLG9taXRlbXB0eRIsCgpvc192ZXJzaW9uGAMgASgJQhjq3h8Ub3NfdmVyc2lvbixvbWl0ZW1wdHkSKAoIb3NfYnVpbGQYBCABKAlCFureHxJvc19idWlsZCxvbWl0ZW1wdHkSMAoMb3NfdXNlcm5hbWVzGAUgAygJQhrq3h8Wb3NfdXNlcm5hbWVzLG9taXRlbXB0eRI+ChNqYW1mX2JpbmFyeV92ZXJzaW9uGAYgASgJQiHq3h8damFtZl9iaW5hcnlfdmVyc2lvbixvbWl0ZW1wdHkSLgoLZXh0ZXJuYWxfaWQYByABKAlCGereHxVleHRlcm5hbF9pZCxvbWl0ZW1wdHkSQgoVb3NfYnVpbGRfc3VwcGxlbWVudGFsGAggASgJQiPq3h8fb3NfYnVpbGRfc3VwcGxlbWVudGFsLG9taXRlbXB0eRIiCgVvc19pZBgJIAEoCUIT6t4fD29zX2lkLG9taXRlbXB0eUI9WitnaXRodWIuY29tL2dyYXZpdGF0aW9uYWwvdGVsZXBvcnQvYXBpL3R5cGVzyOEeAMjiHgHQ4h4BwOMeAWIGcHJvdG8z", [file_gogoproto_gogo, file_google_protobuf_timestamp, file_teleport_legacy_types_types]);

/**
 * DeviceV1 is the resource representation of teleport.devicetrust.v1.Device.
 *
 * @generated from message types.DeviceV1
 */
export type DeviceV1 = Message<"types.DeviceV1"> & {
  /**
   * Header is the common resource header.
   *
   * - Kind is always "device".
   * - SubKind is unused.
   * - Version is equivalent to teleport.devicetrust.v1.Device.api_version.
   * - Metadata.Name is equivalent to teleport.devicetrust.v1.Device.Id.
   *
   * @generated from field: types.ResourceHeader Header = 1;
   */
  Header?: ResourceHeader;

  /**
   * Specification of the device.
   *
   * @generated from field: types.DeviceSpec spec = 5;
   */
  spec?: DeviceSpec;
};

/**
 * Describes the message types.DeviceV1.
 * Use `create(DeviceV1Schema)` to create a new message.
 */
export const DeviceV1Schema: GenMessage<DeviceV1> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 0);

/**
 * DeviceSpec is a device specification.
 * Roughly matches teleport.devicetrust.v1.Device, with some fields changed for
 * better UX.
 *
 * @generated from message types.DeviceSpec
 */
export type DeviceSpec = Message<"types.DeviceSpec"> & {
  /**
   * @generated from field: string os_type = 1;
   */
  osType: string;

  /**
   * @generated from field: string asset_tag = 2;
   */
  assetTag: string;

  /**
   * @generated from field: google.protobuf.Timestamp create_time = 3;
   */
  createTime?: Timestamp;

  /**
   * @generated from field: google.protobuf.Timestamp update_time = 4;
   */
  updateTime?: Timestamp;

  /**
   * @generated from field: string enroll_status = 5;
   */
  enrollStatus: string;

  /**
   * @generated from field: types.DeviceCredential credential = 6;
   */
  credential?: DeviceCredential;

  /**
   * @generated from field: repeated types.DeviceCollectedData collected_data = 7;
   */
  collectedData: DeviceCollectedData[];

  /**
   * @generated from field: types.DeviceSource source = 8;
   */
  source?: DeviceSource;

  /**
   * @generated from field: types.DeviceProfile profile = 9;
   */
  profile?: DeviceProfile;

  /**
   * @generated from field: string owner = 10;
   */
  owner: string;
};

/**
 * Describes the message types.DeviceSpec.
 * Use `create(DeviceSpecSchema)` to create a new message.
 */
export const DeviceSpecSchema: GenMessage<DeviceSpec> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 1);

/**
 * DeviceCredential is the resource representation of
 * teleport.devicetrust.v1.DeviceCredential.
 *
 * @generated from message types.DeviceCredential
 */
export type DeviceCredential = Message<"types.DeviceCredential"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: bytes public_key_der = 2;
   */
  publicKeyDer: Uint8Array;

  /**
   * @generated from field: string device_attestation_type = 3;
   */
  deviceAttestationType: string;

  /**
   * @generated from field: string tpm_ekcert_serial = 4;
   */
  tpmEkcertSerial: string;

  /**
   * @generated from field: bytes tpm_ak_public = 5;
   */
  tpmAkPublic: Uint8Array;
};

/**
 * Describes the message types.DeviceCredential.
 * Use `create(DeviceCredentialSchema)` to create a new message.
 */
export const DeviceCredentialSchema: GenMessage<DeviceCredential> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 2);

/**
 * DeviceCollectedData is the resource representation of
 * teleport.devicetrust.v1.DeviceCollectedData.
 *
 * @generated from message types.DeviceCollectedData
 */
export type DeviceCollectedData = Message<"types.DeviceCollectedData"> & {
  /**
   * @generated from field: google.protobuf.Timestamp collect_time = 1;
   */
  collectTime?: Timestamp;

  /**
   * @generated from field: google.protobuf.Timestamp record_time = 2;
   */
  recordTime?: Timestamp;

  /**
   * @generated from field: string os_type = 3;
   */
  osType: string;

  /**
   * @generated from field: string serial_number = 4;
   */
  serialNumber: string;

  /**
   * @generated from field: string model_identifier = 5;
   */
  modelIdentifier: string;

  /**
   * @generated from field: string os_version = 6;
   */
  osVersion: string;

  /**
   * @generated from field: string os_build = 7;
   */
  osBuild: string;

  /**
   * @generated from field: string os_username = 8;
   */
  osUsername: string;

  /**
   * @generated from field: string jamf_binary_version = 9;
   */
  jamfBinaryVersion: string;

  /**
   * @generated from field: string macos_enrollment_profiles = 10;
   */
  macosEnrollmentProfiles: string;

  /**
   * @generated from field: string reported_asset_tag = 11;
   */
  reportedAssetTag: string;

  /**
   * @generated from field: string system_serial_number = 12;
   */
  systemSerialNumber: string;

  /**
   * @generated from field: string base_board_serial_number = 13;
   */
  baseBoardSerialNumber: string;

  /**
   * @generated from field: types.TPMPlatformAttestation tpm_platform_attestation = 14;
   */
  tpmPlatformAttestation?: TPMPlatformAttestation;

  /**
   * @generated from field: string os_id = 15;
   */
  osId: string;
};

/**
 * Describes the message types.DeviceCollectedData.
 * Use `create(DeviceCollectedDataSchema)` to create a new message.
 */
export const DeviceCollectedDataSchema: GenMessage<DeviceCollectedData> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 3);

/**
 * TPMPCR is the resource representation of teleport.devicetrust.v1.TPMPCR.
 *
 * @generated from message types.TPMPCR
 */
export type TPMPCR = Message<"types.TPMPCR"> & {
  /**
   * @generated from field: int32 index = 1;
   */
  index: number;

  /**
   * @generated from field: bytes digest = 2;
   */
  digest: Uint8Array;

  /**
   * @generated from field: uint64 digest_alg = 3;
   */
  digestAlg: bigint;
};

/**
 * Describes the message types.TPMPCR.
 * Use `create(TPMPCRSchema)` to create a new message.
 */
export const TPMPCRSchema: GenMessage<TPMPCR> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 4);

/**
 * TPMQuote is the resource representation of teleport.devicetrust.v1.TPMQuote.
 *
 * @generated from message types.TPMQuote
 */
export type TPMQuote = Message<"types.TPMQuote"> & {
  /**
   * @generated from field: bytes quote = 1;
   */
  quote: Uint8Array;

  /**
   * @generated from field: bytes signature = 2;
   */
  signature: Uint8Array;
};

/**
 * Describes the message types.TPMQuote.
 * Use `create(TPMQuoteSchema)` to create a new message.
 */
export const TPMQuoteSchema: GenMessage<TPMQuote> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 5);

/**
 * TPMPlatformParameters is the resource representation of
 * teleport.devicetrust.v1.TPMPlatformParameters.
 *
 * @generated from message types.TPMPlatformParameters
 */
export type TPMPlatformParameters = Message<"types.TPMPlatformParameters"> & {
  /**
   * @generated from field: repeated types.TPMQuote quotes = 1;
   */
  quotes: TPMQuote[];

  /**
   * @generated from field: repeated types.TPMPCR pcrs = 2;
   */
  pcrs: TPMPCR[];

  /**
   * @generated from field: bytes event_log = 3;
   */
  eventLog: Uint8Array;
};

/**
 * Describes the message types.TPMPlatformParameters.
 * Use `create(TPMPlatformParametersSchema)` to create a new message.
 */
export const TPMPlatformParametersSchema: GenMessage<TPMPlatformParameters> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 6);

/**
 * TPMPlatformAttestation is the resource representation of
 * teleport.devicetrust.v1.TPMPlatformAttestation.
 *
 * @generated from message types.TPMPlatformAttestation
 */
export type TPMPlatformAttestation = Message<"types.TPMPlatformAttestation"> & {
  /**
   * @generated from field: bytes nonce = 1;
   */
  nonce: Uint8Array;

  /**
   * @generated from field: types.TPMPlatformParameters platform_parameters = 2;
   */
  platformParameters?: TPMPlatformParameters;
};

/**
 * Describes the message types.TPMPlatformAttestation.
 * Use `create(TPMPlatformAttestationSchema)` to create a new message.
 */
export const TPMPlatformAttestationSchema: GenMessage<TPMPlatformAttestation> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 7);

/**
 * DeviceSource is the resource representation of
 * teleport.devicetrust.v1.DeviceSource..
 *
 * @generated from message types.DeviceSource
 */
export type DeviceSource = Message<"types.DeviceSource"> & {
  /**
   * @generated from field: string name = 1;
   */
  name: string;

  /**
   * @generated from field: string origin = 2;
   */
  origin: string;
};

/**
 * Describes the message types.DeviceSource.
 * Use `create(DeviceSourceSchema)` to create a new message.
 */
export const DeviceSourceSchema: GenMessage<DeviceSource> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 8);

/**
 * DeviceProfile is the resource representation of
 * teleport.devicetrust.v1.DeviceProfile.
 *
 * @generated from message types.DeviceProfile
 */
export type DeviceProfile = Message<"types.DeviceProfile"> & {
  /**
   * @generated from field: google.protobuf.Timestamp update_time = 1;
   */
  updateTime?: Timestamp;

  /**
   * @generated from field: string model_identifier = 2;
   */
  modelIdentifier: string;

  /**
   * @generated from field: string os_version = 3;
   */
  osVersion: string;

  /**
   * @generated from field: string os_build = 4;
   */
  osBuild: string;

  /**
   * @generated from field: repeated string os_usernames = 5;
   */
  osUsernames: string[];

  /**
   * @generated from field: string jamf_binary_version = 6;
   */
  jamfBinaryVersion: string;

  /**
   * @generated from field: string external_id = 7;
   */
  externalId: string;

  /**
   * @generated from field: string os_build_supplemental = 8;
   */
  osBuildSupplemental: string;

  /**
   * @generated from field: string os_id = 9;
   */
  osId: string;
};

/**
 * Describes the message types.DeviceProfile.
 * Use `create(DeviceProfileSchema)` to create a new message.
 */
export const DeviceProfileSchema: GenMessage<DeviceProfile> = /*@__PURE__*/
  messageDesc(file_teleport_legacy_types_device, 9);

