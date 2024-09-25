// Teleport
// Copyright (C) 2024 Gravitational, Inc.
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

// @generated by protoc-gen-connect-es v1.5.0 with parameter "target=ts"
// @generated from file teleport/lib/teleterm/vnet/v1/vnet_service.proto (package teleport.lib.teleterm.vnet.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { GetBackgroundItemStatusRequest, GetBackgroundItemStatusResponse, ListDNSZonesRequest, ListDNSZonesResponse, StartRequest, StartResponse, StopRequest, StopResponse } from "./vnet_service_pb.js";
import { MethodKind } from "@bufbuild/protobuf";

/**
 * VnetService provides methods to manage a VNet instance.
 *
 * @generated from service teleport.lib.teleterm.vnet.v1.VnetService
 */
export const VnetService = {
  typeName: "teleport.lib.teleterm.vnet.v1.VnetService",
  methods: {
    /**
     * Start starts VNet.
     *
     * @generated from rpc teleport.lib.teleterm.vnet.v1.VnetService.Start
     */
    start: {
      name: "Start",
      I: StartRequest,
      O: StartResponse,
      kind: MethodKind.Unary,
    },
    /**
     * Stop stops VNet.
     *
     * @generated from rpc teleport.lib.teleterm.vnet.v1.VnetService.Stop
     */
    stop: {
      name: "Stop",
      I: StopRequest,
      O: StopResponse,
      kind: MethodKind.Unary,
    },
    /**
     * ListDNSZones returns DNS zones of all root and leaf clusters with non-expired user certs. This
     * includes the proxy service hostnames and custom DNS zones configured in vnet_config.
     *
     * This is fetched independently of what the Electron app thinks the current state of the cluster
     * looks like, since the VNet admin process also fetches this data independently of the Electron
     * app.
     *
     * Just like the admin process, it skips root and leaf clusters for which the vnet_config couldn't
     * be fetched (due to e.g., a network error or an expired cert).
     *
     * @generated from rpc teleport.lib.teleterm.vnet.v1.VnetService.ListDNSZones
     */
    listDNSZones: {
      name: "ListDNSZones",
      I: ListDNSZonesRequest,
      O: ListDNSZonesResponse,
      kind: MethodKind.Unary,
    },
    /**
     * GetBackgroundItemStatus returns the status of the background item responsible for launching
     * VNet daemon. macOS only. tsh must be compiled with the vnetdaemon build tag.
     *
     * @generated from rpc teleport.lib.teleterm.vnet.v1.VnetService.GetBackgroundItemStatus
     */
    getBackgroundItemStatus: {
      name: "GetBackgroundItemStatus",
      I: GetBackgroundItemStatusRequest,
      O: GetBackgroundItemStatusResponse,
      kind: MethodKind.Unary,
    },
  }
} as const;

