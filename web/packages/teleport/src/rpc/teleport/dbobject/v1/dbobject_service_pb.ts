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

// @generated by protoc-gen-es v2.1.0 with parameter "target=ts"
// @generated from file teleport/dbobject/v1/dbobject_service.proto (package teleport.dbobject.v1, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc, serviceDesc } from "@bufbuild/protobuf/codegenv1";
import type { EmptySchema } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_empty } from "@bufbuild/protobuf/wkt";
import type { DatabaseObject, DatabaseObjectSchema } from "./dbobject_pb";
import { file_teleport_dbobject_v1_dbobject } from "./dbobject_pb";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file teleport/dbobject/v1/dbobject_service.proto.
 */
export const file_teleport_dbobject_v1_dbobject_service: GenFile = /*@__PURE__*/
  fileDesc("Cit0ZWxlcG9ydC9kYm9iamVjdC92MS9kYm9iamVjdF9zZXJ2aWNlLnByb3RvEhR0ZWxlcG9ydC5kYm9iamVjdC52MSJTChtDcmVhdGVEYXRhYmFzZU9iamVjdFJlcXVlc3QSNAoGb2JqZWN0GAEgASgLMiQudGVsZXBvcnQuZGJvYmplY3QudjEuRGF0YWJhc2VPYmplY3QiKAoYR2V0RGF0YWJhc2VPYmplY3RSZXF1ZXN0EgwKBG5hbWUYASABKAkiQwoaTGlzdERhdGFiYXNlT2JqZWN0c1JlcXVlc3QSEQoJcGFnZV9zaXplGAEgASgFEhIKCnBhZ2VfdG9rZW4YAiABKAkibQobTGlzdERhdGFiYXNlT2JqZWN0c1Jlc3BvbnNlEjUKB29iamVjdHMYASADKAsyJC50ZWxlcG9ydC5kYm9iamVjdC52MS5EYXRhYmFzZU9iamVjdBIXCg9uZXh0X3BhZ2VfdG9rZW4YAiABKAkiUwobVXBkYXRlRGF0YWJhc2VPYmplY3RSZXF1ZXN0EjQKBm9iamVjdBgBIAEoCzIkLnRlbGVwb3J0LmRib2JqZWN0LnYxLkRhdGFiYXNlT2JqZWN0IlMKG1Vwc2VydERhdGFiYXNlT2JqZWN0UmVxdWVzdBI0CgZvYmplY3QYASABKAsyJC50ZWxlcG9ydC5kYm9iamVjdC52MS5EYXRhYmFzZU9iamVjdCIrChtEZWxldGVEYXRhYmFzZU9iamVjdFJlcXVlc3QSDAoEbmFtZRgBIAEoCTK0BQoVRGF0YWJhc2VPYmplY3RTZXJ2aWNlEmkKEUdldERhdGFiYXNlT2JqZWN0Ei4udGVsZXBvcnQuZGJvYmplY3QudjEuR2V0RGF0YWJhc2VPYmplY3RSZXF1ZXN0GiQudGVsZXBvcnQuZGJvYmplY3QudjEuRGF0YWJhc2VPYmplY3QSegoTTGlzdERhdGFiYXNlT2JqZWN0cxIwLnRlbGVwb3J0LmRib2JqZWN0LnYxLkxpc3REYXRhYmFzZU9iamVjdHNSZXF1ZXN0GjEudGVsZXBvcnQuZGJvYmplY3QudjEuTGlzdERhdGFiYXNlT2JqZWN0c1Jlc3BvbnNlEm8KFENyZWF0ZURhdGFiYXNlT2JqZWN0EjEudGVsZXBvcnQuZGJvYmplY3QudjEuQ3JlYXRlRGF0YWJhc2VPYmplY3RSZXF1ZXN0GiQudGVsZXBvcnQuZGJvYmplY3QudjEuRGF0YWJhc2VPYmplY3QSbwoUVXBkYXRlRGF0YWJhc2VPYmplY3QSMS50ZWxlcG9ydC5kYm9iamVjdC52MS5VcGRhdGVEYXRhYmFzZU9iamVjdFJlcXVlc3QaJC50ZWxlcG9ydC5kYm9iamVjdC52MS5EYXRhYmFzZU9iamVjdBJvChRVcHNlcnREYXRhYmFzZU9iamVjdBIxLnRlbGVwb3J0LmRib2JqZWN0LnYxLlVwc2VydERhdGFiYXNlT2JqZWN0UmVxdWVzdBokLnRlbGVwb3J0LmRib2JqZWN0LnYxLkRhdGFiYXNlT2JqZWN0EmEKFERlbGV0ZURhdGFiYXNlT2JqZWN0EjEudGVsZXBvcnQuZGJvYmplY3QudjEuRGVsZXRlRGF0YWJhc2VPYmplY3RSZXF1ZXN0GhYuZ29vZ2xlLnByb3RvYnVmLkVtcHR5QlRaUmdpdGh1Yi5jb20vZ3Jhdml0YXRpb25hbC90ZWxlcG9ydC9hcGkvZ2VuL3Byb3RvL2dvL3RlbGVwb3J0L2Rib2JqZWN0L3YxO2Rib2JqZWN0djFiBnByb3RvMw", [file_google_protobuf_empty, file_teleport_dbobject_v1_dbobject]);

/**
 * The request for CreateDatabaseObject.
 *
 * @generated from message teleport.dbobject.v1.CreateDatabaseObjectRequest
 */
export type CreateDatabaseObjectRequest = Message<"teleport.dbobject.v1.CreateDatabaseObjectRequest"> & {
  /**
   * The database object to create.
   *
   * @generated from field: teleport.dbobject.v1.DatabaseObject object = 1;
   */
  object?: DatabaseObject;
};

/**
 * Describes the message teleport.dbobject.v1.CreateDatabaseObjectRequest.
 * Use `create(CreateDatabaseObjectRequestSchema)` to create a new message.
 */
export const CreateDatabaseObjectRequestSchema: GenMessage<CreateDatabaseObjectRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 0);

/**
 * The request for GetDatabaseObject.
 *
 * @generated from message teleport.dbobject.v1.GetDatabaseObjectRequest
 */
export type GetDatabaseObjectRequest = Message<"teleport.dbobject.v1.GetDatabaseObjectRequest"> & {
  /**
   * The name of the database object to fetch.
   *
   * @generated from field: string name = 1;
   */
  name: string;
};

/**
 * Describes the message teleport.dbobject.v1.GetDatabaseObjectRequest.
 * Use `create(GetDatabaseObjectRequestSchema)` to create a new message.
 */
export const GetDatabaseObjectRequestSchema: GenMessage<GetDatabaseObjectRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 1);

/**
 * The request for ListDatabaseObjects.
 *
 * @generated from message teleport.dbobject.v1.ListDatabaseObjectsRequest
 */
export type ListDatabaseObjectsRequest = Message<"teleport.dbobject.v1.ListDatabaseObjectsRequest"> & {
  /**
   * The maximum number of items to return.
   * The server may impose a different page size at its discretion.
   *
   * @generated from field: int32 page_size = 1;
   */
  pageSize: number;

  /**
   * The page_token is the next_page_token value returned from a previous List request, if any.
   *
   * @generated from field: string page_token = 2;
   */
  pageToken: string;
};

/**
 * Describes the message teleport.dbobject.v1.ListDatabaseObjectsRequest.
 * Use `create(ListDatabaseObjectsRequestSchema)` to create a new message.
 */
export const ListDatabaseObjectsRequestSchema: GenMessage<ListDatabaseObjectsRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 2);

/**
 * The response for ListDatabaseObjects.
 *
 * @generated from message teleport.dbobject.v1.ListDatabaseObjectsResponse
 */
export type ListDatabaseObjectsResponse = Message<"teleport.dbobject.v1.ListDatabaseObjectsResponse"> & {
  /**
   * The page of database objects that matched the request.
   *
   * @generated from field: repeated teleport.dbobject.v1.DatabaseObject objects = 1;
   */
  objects: DatabaseObject[];

  /**
   * Token to retrieve the next page of results, or empty if there are no
   * more results in the list.
   *
   * @generated from field: string next_page_token = 2;
   */
  nextPageToken: string;
};

/**
 * Describes the message teleport.dbobject.v1.ListDatabaseObjectsResponse.
 * Use `create(ListDatabaseObjectsResponseSchema)` to create a new message.
 */
export const ListDatabaseObjectsResponseSchema: GenMessage<ListDatabaseObjectsResponse> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 3);

/**
 * The request for UpdateDatabaseObject.
 *
 * @generated from message teleport.dbobject.v1.UpdateDatabaseObjectRequest
 */
export type UpdateDatabaseObjectRequest = Message<"teleport.dbobject.v1.UpdateDatabaseObjectRequest"> & {
  /**
   * The database object to replace.
   *
   * @generated from field: teleport.dbobject.v1.DatabaseObject object = 1;
   */
  object?: DatabaseObject;
};

/**
 * Describes the message teleport.dbobject.v1.UpdateDatabaseObjectRequest.
 * Use `create(UpdateDatabaseObjectRequestSchema)` to create a new message.
 */
export const UpdateDatabaseObjectRequestSchema: GenMessage<UpdateDatabaseObjectRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 4);

/**
 * The request for UpsertDatabaseObject.
 *
 * @generated from message teleport.dbobject.v1.UpsertDatabaseObjectRequest
 */
export type UpsertDatabaseObjectRequest = Message<"teleport.dbobject.v1.UpsertDatabaseObjectRequest"> & {
  /**
   * The database object to create or replace.
   *
   * @generated from field: teleport.dbobject.v1.DatabaseObject object = 1;
   */
  object?: DatabaseObject;
};

/**
 * Describes the message teleport.dbobject.v1.UpsertDatabaseObjectRequest.
 * Use `create(UpsertDatabaseObjectRequestSchema)` to create a new message.
 */
export const UpsertDatabaseObjectRequestSchema: GenMessage<UpsertDatabaseObjectRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 5);

/**
 * The request for DeleteDatabaseObject.
 *
 * @generated from message teleport.dbobject.v1.DeleteDatabaseObjectRequest
 */
export type DeleteDatabaseObjectRequest = Message<"teleport.dbobject.v1.DeleteDatabaseObjectRequest"> & {
  /**
   * The name of the database object to delete.
   *
   * @generated from field: string name = 1;
   */
  name: string;
};

/**
 * Describes the message teleport.dbobject.v1.DeleteDatabaseObjectRequest.
 * Use `create(DeleteDatabaseObjectRequestSchema)` to create a new message.
 */
export const DeleteDatabaseObjectRequestSchema: GenMessage<DeleteDatabaseObjectRequest> = /*@__PURE__*/
  messageDesc(file_teleport_dbobject_v1_dbobject_service, 6);

/**
 * DatabaseObjectService provides methods to manage Teleport DatabaseObjects
 *
 * @generated from service teleport.dbobject.v1.DatabaseObjectService
 */
export const DatabaseObjectService: GenService<{
  /**
   * GetDatabaseObject is used to query a database object resource by its name.
   *
   * This will return a NotFound error if the specified database object does not exist.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.GetDatabaseObject
   */
  getDatabaseObject: {
    methodKind: "unary";
    input: typeof GetDatabaseObjectRequestSchema;
    output: typeof DatabaseObjectSchema;
  },
  /**
   * ListDatabaseObjects is used to query database objects.
   *
   * Follows the pagination semantics of
   * https://cloud.google.com/apis/design/standard_methods#list.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.ListDatabaseObjects
   */
  listDatabaseObjects: {
    methodKind: "unary";
    input: typeof ListDatabaseObjectsRequestSchema;
    output: typeof ListDatabaseObjectsResponseSchema;
  },
  /**
   * CreateDatabaseObject is used to create a database object.
   *
   * This will return an error if a database object by that name already exists.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.CreateDatabaseObject
   */
  createDatabaseObject: {
    methodKind: "unary";
    input: typeof CreateDatabaseObjectRequestSchema;
    output: typeof DatabaseObjectSchema;
  },
  /**
   * UpdateDatabaseObject is used to modify an existing database object.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.UpdateDatabaseObject
   */
  updateDatabaseObject: {
    methodKind: "unary";
    input: typeof UpdateDatabaseObjectRequestSchema;
    output: typeof DatabaseObjectSchema;
  },
  /**
   * UpsertDatabaseObject is used to create or replace an existing database object.
   *
   * Prefer using CreateDatabaseObject and UpdateDatabaseObject.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.UpsertDatabaseObject
   */
  upsertDatabaseObject: {
    methodKind: "unary";
    input: typeof UpsertDatabaseObjectRequestSchema;
    output: typeof DatabaseObjectSchema;
  },
  /**
   * DeleteDatabaseObject is used to delete a specific database object.
   *
   * This will return a NotFound error if the specified database object does not exist.
   *
   * @generated from rpc teleport.dbobject.v1.DatabaseObjectService.DeleteDatabaseObject
   */
  deleteDatabaseObject: {
    methodKind: "unary";
    input: typeof DeleteDatabaseObjectRequestSchema;
    output: typeof EmptySchema;
  },
}> = /*@__PURE__*/
  serviceDesc(file_teleport_dbobject_v1_dbobject_service, 0);

