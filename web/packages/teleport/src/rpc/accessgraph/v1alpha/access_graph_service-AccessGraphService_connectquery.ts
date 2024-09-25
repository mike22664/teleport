//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
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

// @generated by protoc-gen-connect-query v1.4.2 with parameter "target=ts,import_extension=none,ts_nocheck=false"
// @generated from file accessgraph/v1alpha/access_graph_service.proto (package accessgraph.v1alpha, syntax proto3)
/* eslint-disable */

import { MethodKind } from "@bufbuild/protobuf";
import { GetFileRequest, GetFileResponse, QueryRequest, QueryResponse, RegisterRequest, RegisterResponse, ReplaceCAsRequest, ReplaceCAsResponse } from "./access_graph_service_pb";

/**
 * Query queries the access graph.
 * Currently only used by WebUI.
 *
 * @generated from rpc accessgraph.v1alpha.AccessGraphService.Query
 */
export const query = {
  localName: "query",
  name: "Query",
  kind: MethodKind.Unary,
  I: QueryRequest,
  O: QueryResponse,
  service: {
    typeName: "accessgraph.v1alpha.AccessGraphService"
  }
} as const;

/**
 * GetFile gets a static UI file from the access graph container.
 *
 * @generated from rpc accessgraph.v1alpha.AccessGraphService.GetFile
 */
export const getFile = {
  localName: "getFile",
  name: "GetFile",
  kind: MethodKind.Unary,
  I: GetFileRequest,
  O: GetFileResponse,
  service: {
    typeName: "accessgraph.v1alpha.AccessGraphService"
  }
} as const;

/**
 * Register submits a new tenant representing this Teleport cluster to the TAG service,
 * identified by its HostCA certificate.
 * The method is idempotent: it succeeds if the tenant has already registered and has the specific CA associated.
 *
 * This method, unlike all others, expects the client to authenticate using a TLS certificate signed by the registration CA,
 * rather than the Teleport cluster's Host CA.
 *
 * @generated from rpc accessgraph.v1alpha.AccessGraphService.Register
 */
export const register = {
  localName: "register",
  name: "Register",
  kind: MethodKind.Unary,
  I: RegisterRequest,
  O: RegisterResponse,
  service: {
    typeName: "accessgraph.v1alpha.AccessGraphService"
  }
} as const;

/**
 * ReplaceCAs is a request to completely replace the set of Host CAs that authenticate this tenant with the given set.
 * This accommodates Teleport Host CA rotation. In a transition from certificate authority A to authority B,
 * the client is expected to call the RPC as follows:
 * 1. Authenticate via existing authority A and call ReplaceCAs([A, B]) -- introduce the incoming CA
 * 2.a. If rotation succeeds, authenticate via the new authority B and call ReplaceCAs([B]) -- delete the previous CA
 * 2.b. If rotation is rolled back, authenticate via the old authority A and call ReplaceCAs([A]) -- delete the candidate CA
 *
 * @generated from rpc accessgraph.v1alpha.AccessGraphService.ReplaceCAs
 */
export const replaceCAs = {
  localName: "replaceCAs",
  name: "ReplaceCAs",
  kind: MethodKind.Unary,
  I: ReplaceCAsRequest,
  O: ReplaceCAsResponse,
  service: {
    typeName: "accessgraph.v1alpha.AccessGraphService"
  }
} as const;
