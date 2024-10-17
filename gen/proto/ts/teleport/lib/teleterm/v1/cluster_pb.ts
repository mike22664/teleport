/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/v1/cluster.proto" (package "teleport.lib.teleterm.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
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
//
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * Cluster describes cluster fields.
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.Cluster
 */
export interface Cluster {
    /**
     * uri is the cluster resource URI.
     * For root clusters, it has the form of /clusters/:rootClusterId where rootClusterId is the
     * name of the profile, that is the hostname of the proxy used to connect to the root cluster.
     * rootClusterId is not equal to the name of the root cluster.
     *
     * For leaf clusters, it has the form of /clusters/:rootClusterId/leaves/:leafClusterId where
     * leafClusterId is equal to the name property of the cluster.
     *
     * @generated from protobuf field: string uri = 1;
     */
    uri: string;
    /**
     * name is used throughout the Teleport Connect codebase as the cluster name.
     *
     * @generated from protobuf field: string name = 2;
     */
    name: string;
    /**
     * proxy_host is address of the proxy used to connect to this cluster.
     * Always includes port number. Present only for root clusters.
     *
     * Example: "teleport-14-ent.example.com:3090"
     *
     * @generated from protobuf field: string proxy_host = 3;
     */
    proxyHost: string;
    /**
     * connected indicates if connection to the cluster can be established, that is if we have a
     * cert for the cluster that hasn't expired
     *
     * @generated from protobuf field: bool connected = 4;
     */
    connected: boolean;
    /**
     * leaf indicates if this is a leaf cluster
     *
     * @generated from protobuf field: bool leaf = 5;
     */
    leaf: boolean;
    /**
     * logged_in_user is present if the user has logged in to the cluster at least once, even
     * if the cert has since expired. If the cluster was added to the app but the
     * user is yet to log in, logged_in_user is not present.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.LoggedInUser logged_in_user = 7;
     */
    loggedInUser?: LoggedInUser;
    /**
     * features describes the auth servers features.
     * Only present when detailed information is queried from the auth server.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.Features features = 8;
     */
    features?: Features;
    /**
     * auth_cluster_id is the unique cluster ID that is set once
     * during the first auth server startup.
     * Only present when detailed information is queried from the auth server.
     *
     * @generated from protobuf field: string auth_cluster_id = 9;
     */
    authClusterId: string;
    /**
     * ProxyVersion is the cluster proxy's service version.
     * Only present when detailed information is queried from the proxy server.
     *
     * @generated from protobuf field: string proxy_version = 10;
     */
    proxyVersion: string;
    /**
     * show_resources tells if the cluster can show requestable resources on the resources page.
     * Controlled by the cluster config.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ShowResources show_resources = 11;
     */
    showResources: ShowResources;
    /**
     * profile_status_error is set if there was an error when reading the profile.
     * This allows the app to be usable, when one or more profiles cannot be read.
     *
     * @generated from protobuf field: string profile_status_error = 12;
     */
    profileStatusError: string;
}
/**
 * LoggedInUser describes a logged-in user
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.LoggedInUser
 */
export interface LoggedInUser {
    /**
     * name is the user name
     *
     * @generated from protobuf field: string name = 1;
     */
    name: string;
    /**
     * roles is the user roles
     *
     * @generated from protobuf field: repeated string roles = 2;
     */
    roles: string[];
    /**
     * ssh_logins is the user ssh logins
     *
     * @generated from protobuf field: repeated string ssh_logins = 3;
     */
    sshLogins: string[];
    /**
     * acl is a user access control list.
     * It is available only after the cluster details are fetched, as it is not stored on disk.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ACL acl = 4;
     */
    acl?: ACL;
    /**
     * active_requests is an array of request-id strings of active requests
     *
     * @generated from protobuf field: repeated string active_requests = 5;
     */
    activeRequests: string[];
    /**
     * suggested_reviewers for the given user.
     * Only present when detailed information is queried from the auth server.
     *
     * @generated from protobuf field: repeated string suggested_reviewers = 6;
     */
    suggestedReviewers: string[];
    /**
     * requestable_roles for the given user.
     * Only present when detailed information is queried from the auth server.
     *
     * @generated from protobuf field: repeated string requestable_roles = 7;
     */
    requestableRoles: string[];
    /**
     * @generated from protobuf field: teleport.lib.teleterm.v1.LoggedInUser.UserType user_type = 8;
     */
    userType: LoggedInUser_UserType;
}
/**
 * UserType indicates whether the user was created through an SSO provider or in Teleport itself.
 * Only present when detailed information is queried from the auth server.
 *
 * @generated from protobuf enum teleport.lib.teleterm.v1.LoggedInUser.UserType
 */
export enum LoggedInUser_UserType {
    /**
     * @generated from protobuf enum value: USER_TYPE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from protobuf enum value: USER_TYPE_LOCAL = 1;
     */
    LOCAL = 1,
    /**
     * @generated from protobuf enum value: USER_TYPE_SSO = 2;
     */
    SSO = 2
}
/**
 * ACL is the access control list of the user
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.ACL
 */
export interface ACL {
    /**
     * auth_connectors defines access to auth.connectors
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess auth_connectors = 2;
     */
    authConnectors?: ResourceAccess;
    /**
     * Roles defines access to roles
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess roles = 3;
     */
    roles?: ResourceAccess;
    /**
     * Users defines access to users.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess users = 4;
     */
    users?: ResourceAccess;
    /**
     * trusted_clusters defines access to trusted clusters
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess trusted_clusters = 5;
     */
    trustedClusters?: ResourceAccess;
    /**
     * Events defines access to audit logs
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess events = 6;
     */
    events?: ResourceAccess;
    /**
     * Tokens defines access to tokens.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess tokens = 7;
     */
    tokens?: ResourceAccess;
    /**
     * Servers defines access to servers.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess servers = 8;
     */
    servers?: ResourceAccess;
    /**
     * apps defines access to application servers
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess apps = 9;
     */
    apps?: ResourceAccess;
    /**
     * dbs defines access to database servers.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess dbs = 10;
     */
    dbs?: ResourceAccess;
    /**
     * kubeservers defines access to kubernetes servers.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess kubeservers = 11;
     */
    kubeservers?: ResourceAccess;
    /**
     * access_requests defines access to access requests
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess access_requests = 12;
     */
    accessRequests?: ResourceAccess;
    /**
     * recorded_sessions defines access to recorded sessions.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess recorded_sessions = 13;
     */
    recordedSessions?: ResourceAccess;
    /**
     * active_sessions defines access to active sessions.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.ResourceAccess active_sessions = 14;
     */
    activeSessions?: ResourceAccess;
}
/**
 * ResourceAccess describes access verbs
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.ResourceAccess
 */
export interface ResourceAccess {
    /**
     * list determines "list" access
     *
     * @generated from protobuf field: bool list = 1;
     */
    list: boolean;
    /**
     * read determines "read" access
     *
     * @generated from protobuf field: bool read = 2;
     */
    read: boolean;
    /**
     * edit determines "edit" access
     *
     * @generated from protobuf field: bool edit = 3;
     */
    edit: boolean;
    /**
     * create determines "create" access
     *
     * @generated from protobuf field: bool create = 4;
     */
    create: boolean;
    /**
     * delete determines "delete" access
     *
     * @generated from protobuf field: bool delete = 5;
     */
    delete: boolean;
    /**
     * use determines "use" access
     *
     * @generated from protobuf field: bool use = 6;
     */
    use: boolean;
}
/**
 * Features describes the auth servers features
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.Features
 */
export interface Features {
    /**
     * advanced_access_workflows enables search-based access requests
     *
     * @generated from protobuf field: bool advanced_access_workflows = 1;
     */
    advancedAccessWorkflows: boolean;
    /**
     * is_usage_based_billing determines if the cloud user subscription is usage-based (pay-as-you-go).
     *
     * @generated from protobuf field: bool is_usage_based_billing = 2;
     */
    isUsageBasedBilling: boolean;
}
/**
 * ShowResources tells if the cluster can show requestable resources on the resources page.
 *
 * @generated from protobuf enum teleport.lib.teleterm.v1.ShowResources
 */
export enum ShowResources {
    /**
     * @generated from protobuf enum value: SHOW_RESOURCES_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from protobuf enum value: SHOW_RESOURCES_REQUESTABLE = 1;
     */
    REQUESTABLE = 1,
    /**
     * @generated from protobuf enum value: SHOW_RESOURCES_ACCESSIBLE_ONLY = 2;
     */
    ACCESSIBLE_ONLY = 2
}
// @generated message type with reflection information, may provide speed optimized methods
class Cluster$Type extends MessageType<Cluster> {
    constructor() {
        super("teleport.lib.teleterm.v1.Cluster", [
            { no: 1, name: "uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "proxy_host", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "connected", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 5, name: "leaf", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 7, name: "logged_in_user", kind: "message", T: () => LoggedInUser },
            { no: 8, name: "features", kind: "message", T: () => Features },
            { no: 9, name: "auth_cluster_id", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 10, name: "proxy_version", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 11, name: "show_resources", kind: "enum", T: () => ["teleport.lib.teleterm.v1.ShowResources", ShowResources, "SHOW_RESOURCES_"] },
            { no: 12, name: "profile_status_error", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<Cluster>): Cluster {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.uri = "";
        message.name = "";
        message.proxyHost = "";
        message.connected = false;
        message.leaf = false;
        message.authClusterId = "";
        message.proxyVersion = "";
        message.showResources = 0;
        message.profileStatusError = "";
        if (value !== undefined)
            reflectionMergePartial<Cluster>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Cluster): Cluster {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string uri */ 1:
                    message.uri = reader.string();
                    break;
                case /* string name */ 2:
                    message.name = reader.string();
                    break;
                case /* string proxy_host */ 3:
                    message.proxyHost = reader.string();
                    break;
                case /* bool connected */ 4:
                    message.connected = reader.bool();
                    break;
                case /* bool leaf */ 5:
                    message.leaf = reader.bool();
                    break;
                case /* teleport.lib.teleterm.v1.LoggedInUser logged_in_user */ 7:
                    message.loggedInUser = LoggedInUser.internalBinaryRead(reader, reader.uint32(), options, message.loggedInUser);
                    break;
                case /* teleport.lib.teleterm.v1.Features features */ 8:
                    message.features = Features.internalBinaryRead(reader, reader.uint32(), options, message.features);
                    break;
                case /* string auth_cluster_id */ 9:
                    message.authClusterId = reader.string();
                    break;
                case /* string proxy_version */ 10:
                    message.proxyVersion = reader.string();
                    break;
                case /* teleport.lib.teleterm.v1.ShowResources show_resources */ 11:
                    message.showResources = reader.int32();
                    break;
                case /* string profile_status_error */ 12:
                    message.profileStatusError = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Cluster, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string uri = 1; */
        if (message.uri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.uri);
        /* string name = 2; */
        if (message.name !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.name);
        /* string proxy_host = 3; */
        if (message.proxyHost !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.proxyHost);
        /* bool connected = 4; */
        if (message.connected !== false)
            writer.tag(4, WireType.Varint).bool(message.connected);
        /* bool leaf = 5; */
        if (message.leaf !== false)
            writer.tag(5, WireType.Varint).bool(message.leaf);
        /* teleport.lib.teleterm.v1.LoggedInUser logged_in_user = 7; */
        if (message.loggedInUser)
            LoggedInUser.internalBinaryWrite(message.loggedInUser, writer.tag(7, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.Features features = 8; */
        if (message.features)
            Features.internalBinaryWrite(message.features, writer.tag(8, WireType.LengthDelimited).fork(), options).join();
        /* string auth_cluster_id = 9; */
        if (message.authClusterId !== "")
            writer.tag(9, WireType.LengthDelimited).string(message.authClusterId);
        /* string proxy_version = 10; */
        if (message.proxyVersion !== "")
            writer.tag(10, WireType.LengthDelimited).string(message.proxyVersion);
        /* teleport.lib.teleterm.v1.ShowResources show_resources = 11; */
        if (message.showResources !== 0)
            writer.tag(11, WireType.Varint).int32(message.showResources);
        /* string profile_status_error = 12; */
        if (message.profileStatusError !== "")
            writer.tag(12, WireType.LengthDelimited).string(message.profileStatusError);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.Cluster
 */
export const Cluster = new Cluster$Type();
// @generated message type with reflection information, may provide speed optimized methods
class LoggedInUser$Type extends MessageType<LoggedInUser> {
    constructor() {
        super("teleport.lib.teleterm.v1.LoggedInUser", [
            { no: 1, name: "name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "roles", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "ssh_logins", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "acl", kind: "message", T: () => ACL },
            { no: 5, name: "active_requests", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 6, name: "suggested_reviewers", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 7, name: "requestable_roles", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 8, name: "user_type", kind: "enum", T: () => ["teleport.lib.teleterm.v1.LoggedInUser.UserType", LoggedInUser_UserType, "USER_TYPE_"] }
        ]);
    }
    create(value?: PartialMessage<LoggedInUser>): LoggedInUser {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.name = "";
        message.roles = [];
        message.sshLogins = [];
        message.activeRequests = [];
        message.suggestedReviewers = [];
        message.requestableRoles = [];
        message.userType = 0;
        if (value !== undefined)
            reflectionMergePartial<LoggedInUser>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: LoggedInUser): LoggedInUser {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string name */ 1:
                    message.name = reader.string();
                    break;
                case /* repeated string roles */ 2:
                    message.roles.push(reader.string());
                    break;
                case /* repeated string ssh_logins */ 3:
                    message.sshLogins.push(reader.string());
                    break;
                case /* teleport.lib.teleterm.v1.ACL acl */ 4:
                    message.acl = ACL.internalBinaryRead(reader, reader.uint32(), options, message.acl);
                    break;
                case /* repeated string active_requests */ 5:
                    message.activeRequests.push(reader.string());
                    break;
                case /* repeated string suggested_reviewers */ 6:
                    message.suggestedReviewers.push(reader.string());
                    break;
                case /* repeated string requestable_roles */ 7:
                    message.requestableRoles.push(reader.string());
                    break;
                case /* teleport.lib.teleterm.v1.LoggedInUser.UserType user_type */ 8:
                    message.userType = reader.int32();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: LoggedInUser, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string name = 1; */
        if (message.name !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.name);
        /* repeated string roles = 2; */
        for (let i = 0; i < message.roles.length; i++)
            writer.tag(2, WireType.LengthDelimited).string(message.roles[i]);
        /* repeated string ssh_logins = 3; */
        for (let i = 0; i < message.sshLogins.length; i++)
            writer.tag(3, WireType.LengthDelimited).string(message.sshLogins[i]);
        /* teleport.lib.teleterm.v1.ACL acl = 4; */
        if (message.acl)
            ACL.internalBinaryWrite(message.acl, writer.tag(4, WireType.LengthDelimited).fork(), options).join();
        /* repeated string active_requests = 5; */
        for (let i = 0; i < message.activeRequests.length; i++)
            writer.tag(5, WireType.LengthDelimited).string(message.activeRequests[i]);
        /* repeated string suggested_reviewers = 6; */
        for (let i = 0; i < message.suggestedReviewers.length; i++)
            writer.tag(6, WireType.LengthDelimited).string(message.suggestedReviewers[i]);
        /* repeated string requestable_roles = 7; */
        for (let i = 0; i < message.requestableRoles.length; i++)
            writer.tag(7, WireType.LengthDelimited).string(message.requestableRoles[i]);
        /* teleport.lib.teleterm.v1.LoggedInUser.UserType user_type = 8; */
        if (message.userType !== 0)
            writer.tag(8, WireType.Varint).int32(message.userType);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.LoggedInUser
 */
export const LoggedInUser = new LoggedInUser$Type();
// @generated message type with reflection information, may provide speed optimized methods
class ACL$Type extends MessageType<ACL> {
    constructor() {
        super("teleport.lib.teleterm.v1.ACL", [
            { no: 2, name: "auth_connectors", kind: "message", T: () => ResourceAccess },
            { no: 3, name: "roles", kind: "message", T: () => ResourceAccess },
            { no: 4, name: "users", kind: "message", T: () => ResourceAccess },
            { no: 5, name: "trusted_clusters", kind: "message", T: () => ResourceAccess },
            { no: 6, name: "events", kind: "message", T: () => ResourceAccess },
            { no: 7, name: "tokens", kind: "message", T: () => ResourceAccess },
            { no: 8, name: "servers", kind: "message", T: () => ResourceAccess },
            { no: 9, name: "apps", kind: "message", T: () => ResourceAccess },
            { no: 10, name: "dbs", kind: "message", T: () => ResourceAccess },
            { no: 11, name: "kubeservers", kind: "message", T: () => ResourceAccess },
            { no: 12, name: "access_requests", kind: "message", T: () => ResourceAccess },
            { no: 13, name: "recorded_sessions", kind: "message", T: () => ResourceAccess },
            { no: 14, name: "active_sessions", kind: "message", T: () => ResourceAccess }
        ]);
    }
    create(value?: PartialMessage<ACL>): ACL {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<ACL>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ACL): ACL {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* teleport.lib.teleterm.v1.ResourceAccess auth_connectors */ 2:
                    message.authConnectors = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.authConnectors);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess roles */ 3:
                    message.roles = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.roles);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess users */ 4:
                    message.users = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.users);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess trusted_clusters */ 5:
                    message.trustedClusters = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.trustedClusters);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess events */ 6:
                    message.events = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.events);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess tokens */ 7:
                    message.tokens = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.tokens);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess servers */ 8:
                    message.servers = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.servers);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess apps */ 9:
                    message.apps = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.apps);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess dbs */ 10:
                    message.dbs = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.dbs);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess kubeservers */ 11:
                    message.kubeservers = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.kubeservers);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess access_requests */ 12:
                    message.accessRequests = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.accessRequests);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess recorded_sessions */ 13:
                    message.recordedSessions = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.recordedSessions);
                    break;
                case /* teleport.lib.teleterm.v1.ResourceAccess active_sessions */ 14:
                    message.activeSessions = ResourceAccess.internalBinaryRead(reader, reader.uint32(), options, message.activeSessions);
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: ACL, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* teleport.lib.teleterm.v1.ResourceAccess auth_connectors = 2; */
        if (message.authConnectors)
            ResourceAccess.internalBinaryWrite(message.authConnectors, writer.tag(2, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess roles = 3; */
        if (message.roles)
            ResourceAccess.internalBinaryWrite(message.roles, writer.tag(3, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess users = 4; */
        if (message.users)
            ResourceAccess.internalBinaryWrite(message.users, writer.tag(4, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess trusted_clusters = 5; */
        if (message.trustedClusters)
            ResourceAccess.internalBinaryWrite(message.trustedClusters, writer.tag(5, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess events = 6; */
        if (message.events)
            ResourceAccess.internalBinaryWrite(message.events, writer.tag(6, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess tokens = 7; */
        if (message.tokens)
            ResourceAccess.internalBinaryWrite(message.tokens, writer.tag(7, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess servers = 8; */
        if (message.servers)
            ResourceAccess.internalBinaryWrite(message.servers, writer.tag(8, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess apps = 9; */
        if (message.apps)
            ResourceAccess.internalBinaryWrite(message.apps, writer.tag(9, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess dbs = 10; */
        if (message.dbs)
            ResourceAccess.internalBinaryWrite(message.dbs, writer.tag(10, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess kubeservers = 11; */
        if (message.kubeservers)
            ResourceAccess.internalBinaryWrite(message.kubeservers, writer.tag(11, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess access_requests = 12; */
        if (message.accessRequests)
            ResourceAccess.internalBinaryWrite(message.accessRequests, writer.tag(12, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess recorded_sessions = 13; */
        if (message.recordedSessions)
            ResourceAccess.internalBinaryWrite(message.recordedSessions, writer.tag(13, WireType.LengthDelimited).fork(), options).join();
        /* teleport.lib.teleterm.v1.ResourceAccess active_sessions = 14; */
        if (message.activeSessions)
            ResourceAccess.internalBinaryWrite(message.activeSessions, writer.tag(14, WireType.LengthDelimited).fork(), options).join();
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.ACL
 */
export const ACL = new ACL$Type();
// @generated message type with reflection information, may provide speed optimized methods
class ResourceAccess$Type extends MessageType<ResourceAccess> {
    constructor() {
        super("teleport.lib.teleterm.v1.ResourceAccess", [
            { no: 1, name: "list", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 2, name: "read", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 3, name: "edit", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 4, name: "create", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 5, name: "delete", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 6, name: "use", kind: "scalar", T: 8 /*ScalarType.BOOL*/ }
        ]);
    }
    create(value?: PartialMessage<ResourceAccess>): ResourceAccess {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.list = false;
        message.read = false;
        message.edit = false;
        message.create = false;
        message.delete = false;
        message.use = false;
        if (value !== undefined)
            reflectionMergePartial<ResourceAccess>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ResourceAccess): ResourceAccess {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* bool list */ 1:
                    message.list = reader.bool();
                    break;
                case /* bool read */ 2:
                    message.read = reader.bool();
                    break;
                case /* bool edit */ 3:
                    message.edit = reader.bool();
                    break;
                case /* bool create */ 4:
                    message.create = reader.bool();
                    break;
                case /* bool delete */ 5:
                    message.delete = reader.bool();
                    break;
                case /* bool use */ 6:
                    message.use = reader.bool();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: ResourceAccess, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* bool list = 1; */
        if (message.list !== false)
            writer.tag(1, WireType.Varint).bool(message.list);
        /* bool read = 2; */
        if (message.read !== false)
            writer.tag(2, WireType.Varint).bool(message.read);
        /* bool edit = 3; */
        if (message.edit !== false)
            writer.tag(3, WireType.Varint).bool(message.edit);
        /* bool create = 4; */
        if (message.create !== false)
            writer.tag(4, WireType.Varint).bool(message.create);
        /* bool delete = 5; */
        if (message.delete !== false)
            writer.tag(5, WireType.Varint).bool(message.delete);
        /* bool use = 6; */
        if (message.use !== false)
            writer.tag(6, WireType.Varint).bool(message.use);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.ResourceAccess
 */
export const ResourceAccess = new ResourceAccess$Type();
// @generated message type with reflection information, may provide speed optimized methods
class Features$Type extends MessageType<Features> {
    constructor() {
        super("teleport.lib.teleterm.v1.Features", [
            { no: 1, name: "advanced_access_workflows", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 2, name: "is_usage_based_billing", kind: "scalar", T: 8 /*ScalarType.BOOL*/ }
        ]);
    }
    create(value?: PartialMessage<Features>): Features {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.advancedAccessWorkflows = false;
        message.isUsageBasedBilling = false;
        if (value !== undefined)
            reflectionMergePartial<Features>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Features): Features {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* bool advanced_access_workflows */ 1:
                    message.advancedAccessWorkflows = reader.bool();
                    break;
                case /* bool is_usage_based_billing */ 2:
                    message.isUsageBasedBilling = reader.bool();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Features, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* bool advanced_access_workflows = 1; */
        if (message.advancedAccessWorkflows !== false)
            writer.tag(1, WireType.Varint).bool(message.advancedAccessWorkflows);
        /* bool is_usage_based_billing = 2; */
        if (message.isUsageBasedBilling !== false)
            writer.tag(2, WireType.Varint).bool(message.isUsageBasedBilling);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.Features
 */
export const Features = new Features$Type();
