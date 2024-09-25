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
// @generated from file teleport/okta/v1/okta_service.proto (package teleport.okta.v1, syntax proto3)
/* eslint-disable */

import { Empty, MethodKind } from "@bufbuild/protobuf";
import { CreateIntegrationRequest, CreateIntegrationResponse, CreateOktaAssignmentRequest, CreateOktaImportRuleRequest, DeleteAllOktaAssignmentsRequest, DeleteAllOktaImportRulesRequest, DeleteOktaAssignmentRequest, DeleteOktaImportRuleRequest, GetAppsRequest, GetAppsResponse, GetGroupsRequest, GetGroupsResponse, GetOktaAssignmentRequest, GetOktaImportRuleRequest, ListOktaAssignmentsRequest, ListOktaAssignmentsResponse, ListOktaImportRulesRequest, ListOktaImportRulesResponse, UpdateIntegrationRequest, UpdateIntegrationResponse, UpdateOktaAssignmentRequest, UpdateOktaAssignmentStatusRequest, UpdateOktaImportRuleRequest, ValidateClientCredentialsRequest, ValidateClientCredentialsResponse } from "./okta_service_pb";
import { OktaAssignmentV1, OktaImportRuleV1 } from "../../legacy/types/types_pb";

/**
 * ListOktaImportRules returns a paginated list of all Okta import rule resources.
 *
 * @generated from rpc teleport.okta.v1.OktaService.ListOktaImportRules
 */
export const listOktaImportRules = {
  localName: "listOktaImportRules",
  name: "ListOktaImportRules",
  kind: MethodKind.Unary,
  I: ListOktaImportRulesRequest,
  O: ListOktaImportRulesResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * GetOktaImportRule returns the specified Okta import rule resources.
 *
 * @generated from rpc teleport.okta.v1.OktaService.GetOktaImportRule
 */
export const getOktaImportRule = {
  localName: "getOktaImportRule",
  name: "GetOktaImportRule",
  kind: MethodKind.Unary,
  I: GetOktaImportRuleRequest,
  O: OktaImportRuleV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * CreateOktaImportRule creates a new Okta import rule resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.CreateOktaImportRule
 */
export const createOktaImportRule = {
  localName: "createOktaImportRule",
  name: "CreateOktaImportRule",
  kind: MethodKind.Unary,
  I: CreateOktaImportRuleRequest,
  O: OktaImportRuleV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * UpdateOktaImportRule updates an existing Okta import rule resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.UpdateOktaImportRule
 */
export const updateOktaImportRule = {
  localName: "updateOktaImportRule",
  name: "UpdateOktaImportRule",
  kind: MethodKind.Unary,
  I: UpdateOktaImportRuleRequest,
  O: OktaImportRuleV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * DeleteOktaImportRule removes the specified Okta import rule resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.DeleteOktaImportRule
 */
export const deleteOktaImportRule = {
  localName: "deleteOktaImportRule",
  name: "DeleteOktaImportRule",
  kind: MethodKind.Unary,
  I: DeleteOktaImportRuleRequest,
  O: Empty,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * DeleteAllOktaImportRules removes all Okta import rules.
 *
 * @generated from rpc teleport.okta.v1.OktaService.DeleteAllOktaImportRules
 */
export const deleteAllOktaImportRules = {
  localName: "deleteAllOktaImportRules",
  name: "DeleteAllOktaImportRules",
  kind: MethodKind.Unary,
  I: DeleteAllOktaImportRulesRequest,
  O: Empty,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * ListOktaAssignments returns a paginated list of all Okta assignment resources.
 *
 * @generated from rpc teleport.okta.v1.OktaService.ListOktaAssignments
 */
export const listOktaAssignments = {
  localName: "listOktaAssignments",
  name: "ListOktaAssignments",
  kind: MethodKind.Unary,
  I: ListOktaAssignmentsRequest,
  O: ListOktaAssignmentsResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * GetOktaAssignment returns the specified Okta assignment resources.
 *
 * @generated from rpc teleport.okta.v1.OktaService.GetOktaAssignment
 */
export const getOktaAssignment = {
  localName: "getOktaAssignment",
  name: "GetOktaAssignment",
  kind: MethodKind.Unary,
  I: GetOktaAssignmentRequest,
  O: OktaAssignmentV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * CreateOktaAssignment creates a new Okta assignment resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.CreateOktaAssignment
 */
export const createOktaAssignment = {
  localName: "createOktaAssignment",
  name: "CreateOktaAssignment",
  kind: MethodKind.Unary,
  I: CreateOktaAssignmentRequest,
  O: OktaAssignmentV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * UpdateOktaAssignment updates an existing Okta assignment resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.UpdateOktaAssignment
 */
export const updateOktaAssignment = {
  localName: "updateOktaAssignment",
  name: "UpdateOktaAssignment",
  kind: MethodKind.Unary,
  I: UpdateOktaAssignmentRequest,
  O: OktaAssignmentV1,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * UpdateOktaAssignmentStatus will update the status for an Okta assignment.
 *
 * @generated from rpc teleport.okta.v1.OktaService.UpdateOktaAssignmentStatus
 */
export const updateOktaAssignmentStatus = {
  localName: "updateOktaAssignmentStatus",
  name: "UpdateOktaAssignmentStatus",
  kind: MethodKind.Unary,
  I: UpdateOktaAssignmentStatusRequest,
  O: Empty,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * DeleteOktaAssignment removes the specified Okta assignment resource.
 *
 * @generated from rpc teleport.okta.v1.OktaService.DeleteOktaAssignment
 */
export const deleteOktaAssignment = {
  localName: "deleteOktaAssignment",
  name: "DeleteOktaAssignment",
  kind: MethodKind.Unary,
  I: DeleteOktaAssignmentRequest,
  O: Empty,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * DeleteAllOktaAssignments removes all Okta assignments.
 *
 * @generated from rpc teleport.okta.v1.OktaService.DeleteAllOktaAssignments
 */
export const deleteAllOktaAssignments = {
  localName: "deleteAllOktaAssignments",
  name: "DeleteAllOktaAssignments",
  kind: MethodKind.Unary,
  I: DeleteAllOktaAssignmentsRequest,
  O: Empty,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * ValidateClientCredentials checks if the provided client credentials are valid.
 *
 * @generated from rpc teleport.okta.v1.OktaService.ValidateClientCredentials
 */
export const validateClientCredentials = {
  localName: "validateClientCredentials",
  name: "ValidateClientCredentials",
  kind: MethodKind.Unary,
  I: ValidateClientCredentialsRequest,
  O: ValidateClientCredentialsResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * EnrollIntegration enrolls a new integration with the specified parameters.
 *
 * @generated from rpc teleport.okta.v1.OktaService.CreateIntegration
 */
export const createIntegration = {
  localName: "createIntegration",
  name: "CreateIntegration",
  kind: MethodKind.Unary,
  I: CreateIntegrationRequest,
  O: CreateIntegrationResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * UpdateIntegration updates the settings or properties of an existing integration.
 *
 * @generated from rpc teleport.okta.v1.OktaService.UpdateIntegration
 */
export const updateIntegration = {
  localName: "updateIntegration",
  name: "UpdateIntegration",
  kind: MethodKind.Unary,
  I: UpdateIntegrationRequest,
  O: UpdateIntegrationResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * GetApps retrieves a list of apps from Okta based on specified filter criteria.
 *
 * @generated from rpc teleport.okta.v1.OktaService.GetApps
 */
export const getApps = {
  localName: "getApps",
  name: "GetApps",
  kind: MethodKind.Unary,
  I: GetAppsRequest,
  O: GetAppsResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;

/**
 * GetGroups retrieves a list of apps from Okta based on specified filter criteria.
 *
 * @generated from rpc teleport.okta.v1.OktaService.GetGroups
 */
export const getGroups = {
  localName: "getGroups",
  name: "GetGroups",
  kind: MethodKind.Unary,
  I: GetGroupsRequest,
  O: GetGroupsResponse,
  service: {
    typeName: "teleport.okta.v1.OktaService"
  }
} as const;
