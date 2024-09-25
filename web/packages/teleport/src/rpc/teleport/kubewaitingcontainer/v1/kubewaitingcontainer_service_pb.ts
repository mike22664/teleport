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
// @generated from file teleport/kubewaitingcontainer/v1/kubewaitingcontainer_service.proto (package teleport.kubewaitingcontainer.v1, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc, serviceDesc } from "@bufbuild/protobuf/codegenv1";
import type { EmptySchema } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_empty } from "@bufbuild/protobuf/wkt";
import type { KubernetesWaitingContainer, KubernetesWaitingContainerSchema } from "./kubewaitingcontainer_pb";
import { file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer } from "./kubewaitingcontainer_pb";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file teleport/kubewaitingcontainer/v1/kubewaitingcontainer_service.proto.
 */
export const file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service: GenFile = /*@__PURE__*/
  fileDesc("CkN0ZWxlcG9ydC9rdWJld2FpdGluZ2NvbnRhaW5lci92MS9rdWJld2FpdGluZ2NvbnRhaW5lcl9zZXJ2aWNlLnByb3RvEiB0ZWxlcG9ydC5rdWJld2FpdGluZ2NvbnRhaW5lci52MSJPCiZMaXN0S3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJzUmVxdWVzdBIRCglwYWdlX3NpemUYASABKAUSEgoKcGFnZV90b2tlbhgCIAEoCSKcAQonTGlzdEt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyc1Jlc3BvbnNlElgKEndhaXRpbmdfY29udGFpbmVycxgBIAMoCzI8LnRlbGVwb3J0Lmt1YmV3YWl0aW5nY29udGFpbmVyLnYxLkt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyEhcKD25leHRfcGFnZV90b2tlbhgCIAEoCSKGAQokR2V0S3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJSZXF1ZXN0EhAKCHVzZXJuYW1lGAEgASgJEg8KB2NsdXN0ZXIYAiABKAkSEQoJbmFtZXNwYWNlGAMgASgJEhAKCHBvZF9uYW1lGAQgASgJEhYKDmNvbnRhaW5lcl9uYW1lGAUgASgJIoIBCidDcmVhdGVLdWJlcm5ldGVzV2FpdGluZ0NvbnRhaW5lclJlcXVlc3QSVwoRd2FpdGluZ19jb250YWluZXIYASABKAsyPC50ZWxlcG9ydC5rdWJld2FpdGluZ2NvbnRhaW5lci52MS5LdWJlcm5ldGVzV2FpdGluZ0NvbnRhaW5lciKJAQonRGVsZXRlS3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJSZXF1ZXN0EhAKCHVzZXJuYW1lGAEgASgJEg8KB2NsdXN0ZXIYAiABKAkSEQoJbmFtZXNwYWNlGAMgASgJEhAKCHBvZF9uYW1lGAQgASgJEhYKDmNvbnRhaW5lcl9uYW1lGAUgASgJMrUFChxLdWJlV2FpdGluZ0NvbnRhaW5lcnNTZXJ2aWNlErYBCh9MaXN0S3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJzEkgudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuTGlzdEt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyc1JlcXVlc3QaSS50ZWxlcG9ydC5rdWJld2FpdGluZ2NvbnRhaW5lci52MS5MaXN0S3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJzUmVzcG9uc2USpQEKHUdldEt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyEkYudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuR2V0S3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJSZXF1ZXN0GjwudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuS3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXISqwEKIENyZWF0ZUt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyEkkudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuQ3JlYXRlS3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJSZXF1ZXN0GjwudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuS3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXIShQEKIERlbGV0ZUt1YmVybmV0ZXNXYWl0aW5nQ29udGFpbmVyEkkudGVsZXBvcnQua3ViZXdhaXRpbmdjb250YWluZXIudjEuRGVsZXRlS3ViZXJuZXRlc1dhaXRpbmdDb250YWluZXJSZXF1ZXN0GhYuZ29vZ2xlLnByb3RvYnVmLkVtcHR5QmxaamdpdGh1Yi5jb20vZ3Jhdml0YXRpb25hbC90ZWxlcG9ydC9hcGkvZ2VuL3Byb3RvL2dvL3RlbGVwb3J0L2t1YmV3YWl0aW5nY29udGFpbmVyL3YxO2t1YmV3YWl0aW5nY29udGFpbmVydjFiBnByb3RvMw", [file_google_protobuf_empty, file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer]);

/**
 * ListKubernetesWaitingContainersRequest is the request for ListKubernetesWaitingContainers.
 *
 * @generated from message teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersRequest
 */
export type ListKubernetesWaitingContainersRequest = Message<"teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersRequest"> & {
  /**
   * The maximum number of items to return.
   * The server may impose a different page size at its discretion.
   *
   * @generated from field: int32 page_size = 1;
   */
  pageSize: number;

  /**
   * The next_page_token value returned from a previous ListFoo request, if any.
   *
   * @generated from field: string page_token = 2;
   */
  pageToken: string;
};

/**
 * Describes the message teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersRequest.
 * Use `create(ListKubernetesWaitingContainersRequestSchema)` to create a new message.
 */
export const ListKubernetesWaitingContainersRequestSchema: GenMessage<ListKubernetesWaitingContainersRequest> = /*@__PURE__*/
  messageDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 0);

/**
 * ListKubernetesWaitingContainersResponse is the response for ListKubernetesWaitingContainers.
 *
 * @generated from message teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersResponse
 */
export type ListKubernetesWaitingContainersResponse = Message<"teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersResponse"> & {
  /**
   * @generated from field: repeated teleport.kubewaitingcontainer.v1.KubernetesWaitingContainer waiting_containers = 1;
   */
  waitingContainers: KubernetesWaitingContainer[];

  /**
   * Token to retrieve the next page of results, or empty if there are no
   * more results exist.
   *
   * @generated from field: string next_page_token = 2;
   */
  nextPageToken: string;
};

/**
 * Describes the message teleport.kubewaitingcontainer.v1.ListKubernetesWaitingContainersResponse.
 * Use `create(ListKubernetesWaitingContainersResponseSchema)` to create a new message.
 */
export const ListKubernetesWaitingContainersResponseSchema: GenMessage<ListKubernetesWaitingContainersResponse> = /*@__PURE__*/
  messageDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 1);

/**
 * GetKubernetesWaitingContainerRequest is the request for GetKubernetesWaitingContainer.
 *
 * @generated from message teleport.kubewaitingcontainer.v1.GetKubernetesWaitingContainerRequest
 */
export type GetKubernetesWaitingContainerRequest = Message<"teleport.kubewaitingcontainer.v1.GetKubernetesWaitingContainerRequest"> & {
  /**
   * username is the Teleport user that attempted to create the container
   *
   * @generated from field: string username = 1;
   */
  username: string;

  /**
   * cluster is the Kubernetes cluster of this container
   *
   * @generated from field: string cluster = 2;
   */
  cluster: string;

  /**
   * namespace is the Kubernetes namespace of this container
   *
   * @generated from field: string namespace = 3;
   */
  namespace: string;

  /**
   * pod_name is the name of the parent pod
   *
   * @generated from field: string pod_name = 4;
   */
  podName: string;

  /**
   * container_name is the name of the ephemeral container
   *
   * @generated from field: string container_name = 5;
   */
  containerName: string;
};

/**
 * Describes the message teleport.kubewaitingcontainer.v1.GetKubernetesWaitingContainerRequest.
 * Use `create(GetKubernetesWaitingContainerRequestSchema)` to create a new message.
 */
export const GetKubernetesWaitingContainerRequestSchema: GenMessage<GetKubernetesWaitingContainerRequest> = /*@__PURE__*/
  messageDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 2);

/**
 * CreateKubernetesWaitingContainerRequest is the request for CreateKubernetesWaitingContainer.
 *
 * @generated from message teleport.kubewaitingcontainer.v1.CreateKubernetesWaitingContainerRequest
 */
export type CreateKubernetesWaitingContainerRequest = Message<"teleport.kubewaitingcontainer.v1.CreateKubernetesWaitingContainerRequest"> & {
  /**
   * waiting_container is the waiting container resource.
   *
   * @generated from field: teleport.kubewaitingcontainer.v1.KubernetesWaitingContainer waiting_container = 1;
   */
  waitingContainer?: KubernetesWaitingContainer;
};

/**
 * Describes the message teleport.kubewaitingcontainer.v1.CreateKubernetesWaitingContainerRequest.
 * Use `create(CreateKubernetesWaitingContainerRequestSchema)` to create a new message.
 */
export const CreateKubernetesWaitingContainerRequestSchema: GenMessage<CreateKubernetesWaitingContainerRequest> = /*@__PURE__*/
  messageDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 3);

/**
 * DeleteKubernetesWaitingContainerRequest is the request for DeleteKubernetesWaitingContainer.
 *
 * @generated from message teleport.kubewaitingcontainer.v1.DeleteKubernetesWaitingContainerRequest
 */
export type DeleteKubernetesWaitingContainerRequest = Message<"teleport.kubewaitingcontainer.v1.DeleteKubernetesWaitingContainerRequest"> & {
  /**
   * username is the Teleport user that attempted to create the container
   *
   * @generated from field: string username = 1;
   */
  username: string;

  /**
   * cluster is the Kubernetes cluster of this container
   *
   * @generated from field: string cluster = 2;
   */
  cluster: string;

  /**
   * namespace is the Kubernetes namespace of this container
   *
   * @generated from field: string namespace = 3;
   */
  namespace: string;

  /**
   * pod_name is the name of the parent pod
   *
   * @generated from field: string pod_name = 4;
   */
  podName: string;

  /**
   * container_name is the name of the ephemeral container
   *
   * @generated from field: string container_name = 5;
   */
  containerName: string;
};

/**
 * Describes the message teleport.kubewaitingcontainer.v1.DeleteKubernetesWaitingContainerRequest.
 * Use `create(DeleteKubernetesWaitingContainerRequestSchema)` to create a new message.
 */
export const DeleteKubernetesWaitingContainerRequestSchema: GenMessage<DeleteKubernetesWaitingContainerRequest> = /*@__PURE__*/
  messageDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 4);

/**
 * KubeWaitingContainersService manages Kubernetes ephemeral
 * containers that are waiting to be created until moderated
 * session conditions are met.
 *
 * @generated from service teleport.kubewaitingcontainer.v1.KubeWaitingContainersService
 */
export const KubeWaitingContainersService: GenService<{
  /**
   * ListKubernetesWaitingContainers returns a Kubernetes ephemeral
   * container that is waiting to be created.
   *
   * @generated from rpc teleport.kubewaitingcontainer.v1.KubeWaitingContainersService.ListKubernetesWaitingContainers
   */
  listKubernetesWaitingContainers: {
    methodKind: "unary";
    input: typeof ListKubernetesWaitingContainersRequestSchema;
    output: typeof ListKubernetesWaitingContainersResponseSchema;
  },
  /**
   * GetKubernetesWaitingContainer returns a Kubernetes ephemeral
   * container that is waiting to be created.
   *
   * @generated from rpc teleport.kubewaitingcontainer.v1.KubeWaitingContainersService.GetKubernetesWaitingContainer
   */
  getKubernetesWaitingContainer: {
    methodKind: "unary";
    input: typeof GetKubernetesWaitingContainerRequestSchema;
    output: typeof KubernetesWaitingContainerSchema;
  },
  /**
   * CreateKubernetesWaitingContainer creates a Kubernetes ephemeral
   * container that is waiting to be created.
   *
   * @generated from rpc teleport.kubewaitingcontainer.v1.KubeWaitingContainersService.CreateKubernetesWaitingContainer
   */
  createKubernetesWaitingContainer: {
    methodKind: "unary";
    input: typeof CreateKubernetesWaitingContainerRequestSchema;
    output: typeof KubernetesWaitingContainerSchema;
  },
  /**
   * DeleteKubernetesWaitingContainer deletes a Kubernetes ephemeral
   * container that is waiting to be created.
   *
   * @generated from rpc teleport.kubewaitingcontainer.v1.KubeWaitingContainersService.DeleteKubernetesWaitingContainer
   */
  deleteKubernetesWaitingContainer: {
    methodKind: "unary";
    input: typeof DeleteKubernetesWaitingContainerRequestSchema;
    output: typeof EmptySchema;
  },
}> = /*@__PURE__*/
  serviceDesc(file_teleport_kubewaitingcontainer_v1_kubewaitingcontainer_service, 0);

