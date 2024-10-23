// Code generated by goderive DO NOT EDIT.

package types

import (
	"bytes"
)

// deriveTeleportEqualAccessReviewThreshold returns whether this and that are equal.
func deriveTeleportEqualAccessReviewThreshold(this, that *AccessReviewThreshold) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.Filter == that.Filter &&
			this.Approve == that.Approve &&
			this.Deny == that.Deny
}

// deriveTeleportEqualAppV3 returns whether this and that are equal.
func deriveTeleportEqualAppV3(this, that *AppV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqualMetadata(&this.Metadata, &that.Metadata) &&
			deriveTeleportEqual(&this.Spec, &that.Spec)
}

// deriveTeleportEqualAWS returns whether this and that are equal.
func deriveTeleportEqualAWS(this, that *AWS) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Region == that.Region &&
			deriveTeleportEqual_(&this.Redshift, &that.Redshift) &&
			deriveTeleportEqual_1(&this.RDS, &that.RDS) &&
			this.AccountID == that.AccountID &&
			deriveTeleportEqual_2(&this.ElastiCache, &that.ElastiCache) &&
			deriveTeleportEqual_3(&this.SecretStore, &that.SecretStore) &&
			deriveTeleportEqual_4(&this.MemoryDB, &that.MemoryDB) &&
			deriveTeleportEqual_5(&this.RDSProxy, &that.RDSProxy) &&
			deriveTeleportEqual_6(&this.RedshiftServerless, &that.RedshiftServerless) &&
			this.ExternalID == that.ExternalID &&
			this.AssumeRoleARN == that.AssumeRoleARN &&
			deriveTeleportEqual_7(&this.OpenSearch, &that.OpenSearch) &&
			this.IAMPolicyStatus == that.IAMPolicyStatus &&
			deriveTeleportEqual_8(this.SessionTags, that.SessionTags) &&
			deriveTeleportEqual_9(&this.DocumentDB, &that.DocumentDB)
}

// deriveTeleportEqualGCPCloudSQL returns whether this and that are equal.
func deriveTeleportEqualGCPCloudSQL(this, that *GCPCloudSQL) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ProjectID == that.ProjectID &&
			this.InstanceID == that.InstanceID
}

// deriveTeleportEqualAzure returns whether this and that are equal.
func deriveTeleportEqualAzure(this, that *Azure) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.ResourceID == that.ResourceID &&
			deriveTeleportEqual_10(&this.Redis, &that.Redis) &&
			this.IsFlexiServer == that.IsFlexiServer
}

// deriveTeleportEqualDatabaseV3 returns whether this and that are equal.
func deriveTeleportEqualDatabaseV3(this, that *DatabaseV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqualMetadata(&this.Metadata, &that.Metadata) &&
			deriveTeleportEqual_11(&this.Spec, &that.Spec)
}

// deriveTeleportEqualDynamicWindowsDesktopV1 returns whether this and that are equal.
func deriveTeleportEqualDynamicWindowsDesktopV1(this, that *DynamicWindowsDesktopV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqualResourceHeader(&this.ResourceHeader, &that.ResourceHeader) &&
			deriveTeleportEqual_12(&this.Spec, &that.Spec)
}

// deriveTeleportEqualWindowsDesktopV3 returns whether this and that are equal.
func deriveTeleportEqualWindowsDesktopV3(this, that *WindowsDesktopV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqualResourceHeader(&this.ResourceHeader, &that.ResourceHeader) &&
			deriveTeleportEqual_13(&this.Spec, &that.Spec)
}

// deriveTeleportEqualKubeAzure returns whether this and that are equal.
func deriveTeleportEqualKubeAzure(this, that *KubeAzure) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ResourceName == that.ResourceName &&
			this.ResourceGroup == that.ResourceGroup &&
			this.TenantID == that.TenantID &&
			this.SubscriptionID == that.SubscriptionID
}

// deriveTeleportEqualKubeAWS returns whether this and that are equal.
func deriveTeleportEqualKubeAWS(this, that *KubeAWS) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Region == that.Region &&
			this.AccountID == that.AccountID &&
			this.Name == that.Name
}

// deriveTeleportEqualKubeGCP returns whether this and that are equal.
func deriveTeleportEqualKubeGCP(this, that *KubeGCP) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Location == that.Location &&
			this.ProjectID == that.ProjectID &&
			this.Name == that.Name
}

// deriveTeleportEqualKubernetesClusterV3 returns whether this and that are equal.
func deriveTeleportEqualKubernetesClusterV3(this, that *KubernetesClusterV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqualMetadata(&this.Metadata, &that.Metadata) &&
			deriveTeleportEqual_14(&this.Spec, &that.Spec)
}

// deriveTeleportEqualKubernetesServerV3 returns whether this and that are equal.
func deriveTeleportEqualKubernetesServerV3(this, that *KubernetesServerV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqualMetadata(&this.Metadata, &that.Metadata) &&
			deriveTeleportEqual_15(&this.Spec, &that.Spec)
}

// deriveTeleportEqualOktaAssignmentV1 returns whether this and that are equal.
func deriveTeleportEqualOktaAssignmentV1(this, that *OktaAssignmentV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqualResourceHeader(&this.ResourceHeader, &that.ResourceHeader) &&
			deriveTeleportEqual_16(&this.Spec, &that.Spec)
}

// deriveTeleportEqualResourceHeader returns whether this and that are equal.
func deriveTeleportEqualResourceHeader(this, that *ResourceHeader) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqualMetadata(&this.Metadata, &that.Metadata)
}

// deriveTeleportEqualMetadata returns whether this and that are equal.
func deriveTeleportEqualMetadata(this, that *Metadata) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.Namespace == that.Namespace &&
			this.Description == that.Description &&
			deriveTeleportEqual_8(this.Labels, that.Labels) &&
			((this.Expires == nil && that.Expires == nil) || (this.Expires != nil && that.Expires != nil && (*(this.Expires)).Equal(*(that.Expires))))
}

// deriveTeleportEqualUserGroupV1 returns whether this and that are equal.
func deriveTeleportEqualUserGroupV1(this, that *UserGroupV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqualResourceHeader(&this.ResourceHeader, &that.ResourceHeader) &&
			deriveTeleportEqual_17(&this.Spec, &that.Spec)
}

// deriveTeleportEqual returns whether this and that are equal.
func deriveTeleportEqual(this, that *AppSpecV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.URI == that.URI &&
			this.PublicAddr == that.PublicAddr &&
			deriveTeleportEqual_18(this.DynamicLabels, that.DynamicLabels) &&
			this.InsecureSkipVerify == that.InsecureSkipVerify &&
			deriveTeleportEqual_19(this.Rewrite, that.Rewrite) &&
			deriveTeleportEqual_20(this.AWS, that.AWS) &&
			this.Cloud == that.Cloud &&
			deriveTeleportEqual_21(this.UserGroups, that.UserGroups) &&
			this.Integration == that.Integration &&
			deriveTeleportEqual_21(this.RequiredAppNames, that.RequiredAppNames) &&
			deriveTeleportEqual_22(this.CORS, that.CORS)
}

// deriveTeleportEqual_ returns whether this and that are equal.
func deriveTeleportEqual_(this, that *Redshift) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ClusterID == that.ClusterID
}

// deriveTeleportEqual_1 returns whether this and that are equal.
func deriveTeleportEqual_1(this, that *RDS) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.InstanceID == that.InstanceID &&
			this.ClusterID == that.ClusterID &&
			this.ResourceID == that.ResourceID &&
			this.IAMAuth == that.IAMAuth &&
			deriveTeleportEqual_21(this.Subnets, that.Subnets) &&
			this.VPCID == that.VPCID &&
			deriveTeleportEqual_21(this.SecurityGroups, that.SecurityGroups)
}

// deriveTeleportEqual_2 returns whether this and that are equal.
func deriveTeleportEqual_2(this, that *ElastiCache) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ReplicationGroupID == that.ReplicationGroupID &&
			deriveTeleportEqual_21(this.UserGroupIDs, that.UserGroupIDs) &&
			this.TransitEncryptionEnabled == that.TransitEncryptionEnabled &&
			this.EndpointType == that.EndpointType
}

// deriveTeleportEqual_3 returns whether this and that are equal.
func deriveTeleportEqual_3(this, that *SecretStore) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.KeyPrefix == that.KeyPrefix &&
			this.KMSKeyID == that.KMSKeyID
}

// deriveTeleportEqual_4 returns whether this and that are equal.
func deriveTeleportEqual_4(this, that *MemoryDB) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ClusterName == that.ClusterName &&
			this.ACLName == that.ACLName &&
			this.TLSEnabled == that.TLSEnabled &&
			this.EndpointType == that.EndpointType
}

// deriveTeleportEqual_5 returns whether this and that are equal.
func deriveTeleportEqual_5(this, that *RDSProxy) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.CustomEndpointName == that.CustomEndpointName &&
			this.ResourceID == that.ResourceID
}

// deriveTeleportEqual_6 returns whether this and that are equal.
func deriveTeleportEqual_6(this, that *RedshiftServerless) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.WorkgroupName == that.WorkgroupName &&
			this.EndpointName == that.EndpointName &&
			this.WorkgroupID == that.WorkgroupID
}

// deriveTeleportEqual_7 returns whether this and that are equal.
func deriveTeleportEqual_7(this, that *OpenSearch) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.DomainName == that.DomainName &&
			this.DomainID == that.DomainID &&
			this.EndpointType == that.EndpointType
}

// deriveTeleportEqual_8 returns whether this and that are equal.
func deriveTeleportEqual_8(this, that map[string]string) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for k, v := range this {
		thatv, ok := that[k]
		if !ok {
			return false
		}
		if !(v == thatv) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_9 returns whether this and that are equal.
func deriveTeleportEqual_9(this, that *DocumentDB) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ClusterID == that.ClusterID &&
			this.InstanceID == that.InstanceID &&
			this.EndpointType == that.EndpointType
}

// deriveTeleportEqual_10 returns whether this and that are equal.
func deriveTeleportEqual_10(this, that *AzureRedis) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ClusteringPolicy == that.ClusteringPolicy
}

// deriveTeleportEqual_11 returns whether this and that are equal.
func deriveTeleportEqual_11(this, that *DatabaseSpecV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Protocol == that.Protocol &&
			this.URI == that.URI &&
			this.CACert == that.CACert &&
			deriveTeleportEqual_18(this.DynamicLabels, that.DynamicLabels) &&
			deriveTeleportEqualAWS(&this.AWS, &that.AWS) &&
			deriveTeleportEqualGCPCloudSQL(&this.GCP, &that.GCP) &&
			deriveTeleportEqualAzure(&this.Azure, &that.Azure) &&
			deriveTeleportEqual_23(&this.TLS, &that.TLS) &&
			deriveTeleportEqual_24(&this.AD, &that.AD) &&
			deriveTeleportEqual_25(&this.MySQL, &that.MySQL) &&
			deriveTeleportEqual_26(this.AdminUser, that.AdminUser) &&
			deriveTeleportEqual_27(&this.MongoAtlas, &that.MongoAtlas) &&
			deriveTeleportEqual_28(&this.Oracle, &that.Oracle)
}

// deriveTeleportEqual_12 returns whether this and that are equal.
func deriveTeleportEqual_12(this, that *DynamicWindowsDesktopSpecV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Addr == that.Addr &&
			this.Domain == that.Domain &&
			this.NonAD == that.NonAD &&
			deriveTeleportEqual_29(this.ScreenSize, that.ScreenSize)
}

// deriveTeleportEqual_13 returns whether this and that are equal.
func deriveTeleportEqual_13(this, that *WindowsDesktopSpecV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Addr == that.Addr &&
			this.Domain == that.Domain &&
			this.HostID == that.HostID &&
			this.NonAD == that.NonAD &&
			deriveTeleportEqual_29(this.ScreenSize, that.ScreenSize)
}

// deriveTeleportEqual_14 returns whether this and that are equal.
func deriveTeleportEqual_14(this, that *KubernetesClusterSpecV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_18(this.DynamicLabels, that.DynamicLabels) &&
			bytes.Equal(this.Kubeconfig, that.Kubeconfig) &&
			deriveTeleportEqualKubeAzure(&this.Azure, &that.Azure) &&
			deriveTeleportEqualKubeAWS(&this.AWS, &that.AWS) &&
			deriveTeleportEqualKubeGCP(&this.GCP, &that.GCP)
}

// deriveTeleportEqual_15 returns whether this and that are equal.
func deriveTeleportEqual_15(this, that *KubernetesServerSpecV3) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Version == that.Version &&
			this.Hostname == that.Hostname &&
			this.HostID == that.HostID &&
			deriveTeleportEqual_30(&this.Rotation, &that.Rotation) &&
			deriveTeleportEqualKubernetesClusterV3(this.Cluster, that.Cluster) &&
			deriveTeleportEqual_21(this.ProxyIDs, that.ProxyIDs)
}

// deriveTeleportEqual_16 returns whether this and that are equal.
func deriveTeleportEqual_16(this, that *OktaAssignmentSpecV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.User == that.User &&
			deriveTeleportEqual_31(this.Targets, that.Targets) &&
			this.CleanupTime.Equal(that.CleanupTime) &&
			this.Status == that.Status &&
			this.LastTransition.Equal(that.LastTransition) &&
			this.Finalized == that.Finalized
}

// deriveTeleportEqual_17 returns whether this and that are equal.
func deriveTeleportEqual_17(this, that *UserGroupSpecV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_21(this.Applications, that.Applications)
}

// deriveTeleportEqual_18 returns whether this and that are equal.
func deriveTeleportEqual_18(this, that map[string]CommandLabelV2) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for k, v := range this {
		thatv, ok := that[k]
		if !ok {
			return false
		}
		if !(deriveTeleportEqual_32(&v, &thatv)) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_19 returns whether this and that are equal.
func deriveTeleportEqual_19(this, that *Rewrite) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_21(this.Redirect, that.Redirect) &&
			deriveTeleportEqual_33(this.Headers, that.Headers) &&
			this.JWTClaims == that.JWTClaims
}

// deriveTeleportEqual_20 returns whether this and that are equal.
func deriveTeleportEqual_20(this, that *AppAWS) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ExternalID == that.ExternalID
}

// deriveTeleportEqual_21 returns whether this and that are equal.
func deriveTeleportEqual_21(this, that []string) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(this[i] == that[i]) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_22 returns whether this and that are equal.
func deriveTeleportEqual_22(this, that *CORSPolicy) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_21(this.AllowedOrigins, that.AllowedOrigins) &&
			deriveTeleportEqual_21(this.AllowedMethods, that.AllowedMethods) &&
			deriveTeleportEqual_21(this.AllowedHeaders, that.AllowedHeaders) &&
			this.AllowCredentials == that.AllowCredentials &&
			this.MaxAge == that.MaxAge &&
			deriveTeleportEqual_21(this.ExposedHeaders, that.ExposedHeaders)
}

// deriveTeleportEqual_23 returns whether this and that are equal.
func deriveTeleportEqual_23(this, that *DatabaseTLS) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Mode == that.Mode &&
			this.CACert == that.CACert &&
			this.ServerName == that.ServerName &&
			this.TrustSystemCertPool == that.TrustSystemCertPool
}

// deriveTeleportEqual_24 returns whether this and that are equal.
func deriveTeleportEqual_24(this, that *AD) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.KeytabFile == that.KeytabFile &&
			this.Krb5File == that.Krb5File &&
			this.Domain == that.Domain &&
			this.SPN == that.SPN &&
			this.LDAPCert == that.LDAPCert &&
			this.KDCHostName == that.KDCHostName
}

// deriveTeleportEqual_25 returns whether this and that are equal.
func deriveTeleportEqual_25(this, that *MySQLOptions) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ServerVersion == that.ServerVersion
}

// deriveTeleportEqual_26 returns whether this and that are equal.
func deriveTeleportEqual_26(this, that *DatabaseAdminUser) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.DefaultDatabase == that.DefaultDatabase
}

// deriveTeleportEqual_27 returns whether this and that are equal.
func deriveTeleportEqual_27(this, that *MongoAtlas) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name
}

// deriveTeleportEqual_28 returns whether this and that are equal.
func deriveTeleportEqual_28(this, that *OracleOptions) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.AuditUser == that.AuditUser
}

// deriveTeleportEqual_29 returns whether this and that are equal.
func deriveTeleportEqual_29(this, that *Resolution) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Width == that.Width &&
			this.Height == that.Height
}

// deriveTeleportEqual_30 returns whether this and that are equal.
func deriveTeleportEqual_30(this, that *Rotation) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.State == that.State &&
			this.Phase == that.Phase &&
			this.Mode == that.Mode &&
			this.CurrentID == that.CurrentID &&
			this.Started.Equal(that.Started) &&
			this.GracePeriod == that.GracePeriod &&
			this.LastRotated.Equal(that.LastRotated) &&
			deriveTeleportEqual_34(&this.Schedule, &that.Schedule)
}

// deriveTeleportEqual_31 returns whether this and that are equal.
func deriveTeleportEqual_31(this, that []*OktaAssignmentTargetV1) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_35(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_32 returns whether this and that are equal.
func deriveTeleportEqual_32(this, that *CommandLabelV2) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Period == that.Period &&
			deriveTeleportEqual_21(this.Command, that.Command) &&
			this.Result == that.Result
}

// deriveTeleportEqual_33 returns whether this and that are equal.
func deriveTeleportEqual_33(this, that []*Header) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_36(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_34 returns whether this and that are equal.
func deriveTeleportEqual_34(this, that *RotationSchedule) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.UpdateClients.Equal(that.UpdateClients) &&
			this.UpdateServers.Equal(that.UpdateServers) &&
			this.Standby.Equal(that.Standby)
}

// deriveTeleportEqual_35 returns whether this and that are equal.
func deriveTeleportEqual_35(this, that *OktaAssignmentTargetV1) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Type == that.Type &&
			this.Id == that.Id
}

// deriveTeleportEqual_36 returns whether this and that are equal.
func deriveTeleportEqual_36(this, that *Header) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.Value == that.Value
}
