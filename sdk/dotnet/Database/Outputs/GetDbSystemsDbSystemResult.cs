// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetDbSystemsDbSystemResult
    {
        /// <summary>
        /// A filter to return only resources that match the given availability domain exactly.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
        /// </summary>
        public readonly ImmutableArray<string> BackupNetworkNsgIds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet the DB system is associated with. Applicable only to Exadata DB systems.
        /// </summary>
        public readonly string BackupSubnetId;
        /// <summary>
        /// The cluster name for Exadata and 2-node RAC virtual machine DB systems. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
        /// </summary>
        public readonly string ClusterName;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The number of CPU cores enabled on the DB system.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemDataCollectionOptionResult> DataCollectionOptions;
        /// <summary>
        /// The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 40 and 80. The default is 80 percent assigned to DATA storage. Not applicable for virtual machine DB systems. Required for BMDBs.
        /// </summary>
        public readonly int DataStoragePercentage;
        /// <summary>
        /// The data storage size, in gigabytes, that is currently available to the DB system. Applies only for virtual machine DB systems. Required for VMDBs.
        /// </summary>
        public readonly int DataStorageSizeInGb;
        /// <summary>
        /// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
        /// </summary>
        public readonly string DatabaseEdition;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemDbHomeResult> DbHomes;
        /// <summary>
        /// The DB system options.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemDbSystemOptionResult> DbSystemOptions;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The type of redundancy configured for the DB system. NORMAL is 2-way redundancy. HIGH is 3-way redundancy.
        /// </summary>
        public readonly string DiskRedundancy;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The domain name for the DB system.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// List of the Fault Domains in which this DB system is provisioned.
        /// </summary>
        public readonly ImmutableArray<string> FaultDomains;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The hostname for the DB system.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemIormConfigCachResult> IormConfigCaches;
        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        public readonly string KmsKeyId;
        public readonly string KmsKeyVersionId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        /// </summary>
        public readonly string LastMaintenanceRunId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
        /// </summary>
        public readonly string LastPatchHistoryEntryId;
        /// <summary>
        /// The Oracle license model that applies to all the databases on the DB system. The default is LICENSE_INCLUDED.
        /// </summary>
        public readonly string LicenseModel;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The port number configured for the listener on the DB system.
        /// </summary>
        public readonly int ListenerPort;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemMaintenanceWindowDetailResult> MaintenanceWindowDetails;
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemMaintenanceWindowResult> MaintenanceWindows;
        /// <summary>
        /// Memory allocated to the DB system, in gigabytes.
        /// </summary>
        public readonly int MemorySizeInGbs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        /// </summary>
        public readonly string NextMaintenanceRunId;
        /// <summary>
        /// The number of nodes in the DB system. For RAC DB systems, the value is greater than 1.
        /// </summary>
        public readonly int NodeCount;
        /// <summary>
        /// The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the network security groups (NSGs) to which this resource belongs. Setting this to an empty list removes all resources from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
        /// * A network security group (NSG) is optional for Autonomous Databases with private access. The nsgIds list can be empty.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The most recent OS Patch Version applied on the DB system.
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// The point in time for a cloned database system when the data disks were cloned from the source database system, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        public readonly string PointInTimeDataDiskCloneTimestamp;
        public readonly string PrivateIp;
        public readonly string PrivateIpV6;
        /// <summary>
        /// The RECO/REDO storage size, in gigabytes, that is currently allocated to the DB system. Applies only for virtual machine DB systems.
        /// </summary>
        public readonly int RecoStorageSizeInGb;
        /// <summary>
        /// The FQDN of the DNS record for the SCAN IP addresses that are associated with the DB system.
        /// </summary>
        public readonly string ScanDnsName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DNS record for the SCAN IP addresses that are associated with the DB system.
        /// </summary>
        public readonly string ScanDnsRecordId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IPv4 addresses associated with the DB system. SCAN IPv4 addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
        /// </summary>
        public readonly ImmutableArray<string> ScanIpIds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IPv6 addresses associated with the DB system. SCAN IPv6 addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
        /// </summary>
        public readonly ImmutableArray<string> ScanIpv6ids;
        /// <summary>
        /// Security Attributes for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Oracle-ZPR": {"MaxEgressCount": {"value": "42", "mode": "audit"}}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SecurityAttributes;
        /// <summary>
        /// The shape of the DB system. The shape determines resources to allocate to the DB system.
        /// * For virtual machine shapes, the number of CPU cores and memory
        /// * For bare metal and Exadata shapes, the number of CPU cores, storage, and memory
        /// </summary>
        public readonly string Shape;
        public readonly string Source;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        public readonly string SourceDbSystemId;
        /// <summary>
        /// True, if Sparse Diskgroup is configured for Exadata dbsystem, False, if Sparse diskgroup was not configured. Only applied for Exadata shape.
        /// </summary>
        public readonly bool SparseDiskgroup;
        /// <summary>
        /// The public key portion of one or more key pairs used for SSH access to the DB system.
        /// </summary>
        public readonly ImmutableArray<string> SshPublicKeys;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The block storage volume performance level. Valid values are `BALANCED` and `HIGH_PERFORMANCE`. See [Block Volume Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm) for more information.
        /// </summary>
        public readonly string StorageVolumePerformanceMode;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the DB system is associated with.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the DB system was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time zone of the DB system. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        public readonly string TimeZone;
        /// <summary>
        /// The Oracle Database version of the DB system.
        /// </summary>
        public readonly string Version;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IPv4 (VIP) addresses associated with the DB system. The Cluster Ready Services (CRS) creates and maintains one VIPv4 address for each node in the DB system to enable failover. If one node fails, the VIPv4 is reassigned to another active node in the cluster.
        /// </summary>
        public readonly ImmutableArray<string> VipIds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IPv6 (VIP) addresses associated with the DB system. The Cluster Ready Services (CRS) creates and maintains one VIP IpV6 address for each node in the DB system to enable failover. If one node fails, the VIP is reassigned to another active node in the cluster.
        /// </summary>
        public readonly ImmutableArray<string> Vipv6ids;
        /// <summary>
        /// The OCID of the zone the DB system is associated with.
        /// </summary>
        public readonly string ZoneId;

        [OutputConstructor]
        private GetDbSystemsDbSystemResult(
            string availabilityDomain,

            ImmutableArray<string> backupNetworkNsgIds,

            string backupSubnetId,

            string clusterName,

            string compartmentId,

            int cpuCoreCount,

            ImmutableArray<Outputs.GetDbSystemsDbSystemDataCollectionOptionResult> dataCollectionOptions,

            int dataStoragePercentage,

            int dataStorageSizeInGb,

            string databaseEdition,

            ImmutableArray<Outputs.GetDbSystemsDbSystemDbHomeResult> dbHomes,

            ImmutableArray<Outputs.GetDbSystemsDbSystemDbSystemOptionResult> dbSystemOptions,

            ImmutableDictionary<string, string> definedTags,

            string diskRedundancy,

            string displayName,

            string domain,

            ImmutableArray<string> faultDomains,

            ImmutableDictionary<string, string> freeformTags,

            string hostname,

            string id,

            ImmutableArray<Outputs.GetDbSystemsDbSystemIormConfigCachResult> iormConfigCaches,

            string kmsKeyId,

            string kmsKeyVersionId,

            string lastMaintenanceRunId,

            string lastPatchHistoryEntryId,

            string licenseModel,

            string lifecycleDetails,

            int listenerPort,

            ImmutableArray<Outputs.GetDbSystemsDbSystemMaintenanceWindowDetailResult> maintenanceWindowDetails,

            ImmutableArray<Outputs.GetDbSystemsDbSystemMaintenanceWindowResult> maintenanceWindows,

            int memorySizeInGbs,

            string nextMaintenanceRunId,

            int nodeCount,

            ImmutableArray<string> nsgIds,

            string osVersion,

            string pointInTimeDataDiskCloneTimestamp,

            string privateIp,

            string privateIpV6,

            int recoStorageSizeInGb,

            string scanDnsName,

            string scanDnsRecordId,

            ImmutableArray<string> scanIpIds,

            ImmutableArray<string> scanIpv6ids,

            ImmutableDictionary<string, string> securityAttributes,

            string shape,

            string source,

            string sourceDbSystemId,

            bool sparseDiskgroup,

            ImmutableArray<string> sshPublicKeys,

            string state,

            string storageVolumePerformanceMode,

            string subnetId,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeZone,

            string version,

            ImmutableArray<string> vipIds,

            ImmutableArray<string> vipv6ids,

            string zoneId)
        {
            AvailabilityDomain = availabilityDomain;
            BackupNetworkNsgIds = backupNetworkNsgIds;
            BackupSubnetId = backupSubnetId;
            ClusterName = clusterName;
            CompartmentId = compartmentId;
            CpuCoreCount = cpuCoreCount;
            DataCollectionOptions = dataCollectionOptions;
            DataStoragePercentage = dataStoragePercentage;
            DataStorageSizeInGb = dataStorageSizeInGb;
            DatabaseEdition = databaseEdition;
            DbHomes = dbHomes;
            DbSystemOptions = dbSystemOptions;
            DefinedTags = definedTags;
            DiskRedundancy = diskRedundancy;
            DisplayName = displayName;
            Domain = domain;
            FaultDomains = faultDomains;
            FreeformTags = freeformTags;
            Hostname = hostname;
            Id = id;
            IormConfigCaches = iormConfigCaches;
            KmsKeyId = kmsKeyId;
            KmsKeyVersionId = kmsKeyVersionId;
            LastMaintenanceRunId = lastMaintenanceRunId;
            LastPatchHistoryEntryId = lastPatchHistoryEntryId;
            LicenseModel = licenseModel;
            LifecycleDetails = lifecycleDetails;
            ListenerPort = listenerPort;
            MaintenanceWindowDetails = maintenanceWindowDetails;
            MaintenanceWindows = maintenanceWindows;
            MemorySizeInGbs = memorySizeInGbs;
            NextMaintenanceRunId = nextMaintenanceRunId;
            NodeCount = nodeCount;
            NsgIds = nsgIds;
            OsVersion = osVersion;
            PointInTimeDataDiskCloneTimestamp = pointInTimeDataDiskCloneTimestamp;
            PrivateIp = privateIp;
            PrivateIpV6 = privateIpV6;
            RecoStorageSizeInGb = recoStorageSizeInGb;
            ScanDnsName = scanDnsName;
            ScanDnsRecordId = scanDnsRecordId;
            ScanIpIds = scanIpIds;
            ScanIpv6ids = scanIpv6ids;
            SecurityAttributes = securityAttributes;
            Shape = shape;
            Source = source;
            SourceDbSystemId = sourceDbSystemId;
            SparseDiskgroup = sparseDiskgroup;
            SshPublicKeys = sshPublicKeys;
            State = state;
            StorageVolumePerformanceMode = storageVolumePerformanceMode;
            SubnetId = subnetId;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeZone = timeZone;
            Version = version;
            VipIds = vipIds;
            Vipv6ids = vipv6ids;
            ZoneId = zoneId;
        }
    }
}
