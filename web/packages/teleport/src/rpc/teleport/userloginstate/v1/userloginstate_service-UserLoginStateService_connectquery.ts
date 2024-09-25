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
// @generated from file teleport/userloginstate/v1/userloginstate_service.proto (package teleport.userloginstate.v1, syntax proto3)
/* eslint-disable */

import { Empty, MethodKind } from "@bufbuild/protobuf";
import { DeleteAllUserLoginStatesRequest, DeleteUserLoginStateRequest, GetUserLoginStateRequest, GetUserLoginStatesRequest, GetUserLoginStatesResponse, UpsertUserLoginStateRequest } from "./userloginstate_service_pb";
import { UserLoginState } from "./userloginstate_pb";

/**
 * GetUserLoginStates returns a list of all user login states.
 *
 * @generated from rpc teleport.userloginstate.v1.UserLoginStateService.GetUserLoginStates
 */
export const getUserLoginStates = {
  localName: "getUserLoginStates",
  name: "GetUserLoginStates",
  kind: MethodKind.Unary,
  I: GetUserLoginStatesRequest,
  O: GetUserLoginStatesResponse,
  service: {
    typeName: "teleport.userloginstate.v1.UserLoginStateService"
  }
} as const;

/**
 * GetUserLoginState returns the specified user login state resource.
 *
 * @generated from rpc teleport.userloginstate.v1.UserLoginStateService.GetUserLoginState
 */
export const getUserLoginState = {
  localName: "getUserLoginState",
  name: "GetUserLoginState",
  kind: MethodKind.Unary,
  I: GetUserLoginStateRequest,
  O: UserLoginState,
  service: {
    typeName: "teleport.userloginstate.v1.UserLoginStateService"
  }
} as const;

/**
 * UpsertUserLoginState creates or updates a user login state resource.
 *
 * @generated from rpc teleport.userloginstate.v1.UserLoginStateService.UpsertUserLoginState
 */
export const upsertUserLoginState = {
  localName: "upsertUserLoginState",
  name: "UpsertUserLoginState",
  kind: MethodKind.Unary,
  I: UpsertUserLoginStateRequest,
  O: UserLoginState,
  service: {
    typeName: "teleport.userloginstate.v1.UserLoginStateService"
  }
} as const;

/**
 * DeleteUserLoginState hard deletes the specified user login state resource.
 *
 * @generated from rpc teleport.userloginstate.v1.UserLoginStateService.DeleteUserLoginState
 */
export const deleteUserLoginState = {
  localName: "deleteUserLoginState",
  name: "DeleteUserLoginState",
  kind: MethodKind.Unary,
  I: DeleteUserLoginStateRequest,
  O: Empty,
  service: {
    typeName: "teleport.userloginstate.v1.UserLoginStateService"
  }
} as const;

/**
 * DeleteAllUserLoginStates hard deletes all user login states.
 *
 * @generated from rpc teleport.userloginstate.v1.UserLoginStateService.DeleteAllUserLoginStates
 */
export const deleteAllUserLoginStates = {
  localName: "deleteAllUserLoginStates",
  name: "DeleteAllUserLoginStates",
  kind: MethodKind.Unary,
  I: DeleteAllUserLoginStatesRequest,
  O: Empty,
  service: {
    typeName: "teleport.userloginstate.v1.UserLoginStateService"
  }
} as const;
