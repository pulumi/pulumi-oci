// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GloballyDistributedDatabase.Outputs
{

    [OutputType]
    public sealed class ShardedDatabaseCatalogDetail
    {
        /// <summary>
        /// Admin password for the catalog database.
        /// </summary>
        public readonly string AdminPassword;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
        /// </summary>
        public readonly string CloudAutonomousVmClusterId;
        /// <summary>
        /// The compute count for the catalog database. It has to be in multiple of 2.
        /// </summary>
        public readonly double ComputeCount;
        /// <summary>
        /// Identifier of the underlying container database.
        /// </summary>
        public readonly string? ContainerDatabaseId;
        /// <summary>
        /// Identifier of the underlying container database parent.
        /// </summary>
        public readonly string? ContainerDatabaseParentId;
        /// <summary>
        /// The data disk group size to be allocated in GBs for the catalog database.
        /// </summary>
        public readonly double DataStorageSizeInGbs;
        /// <summary>
        /// Details of encryption key to be used to encrypt data for shards and catalog for sharded database. For system-defined sharding type, all shards have to use same encryptionKeyDetails. For system-defined sharding, if encryptionKeyDetails are not specified for catalog, then Oracle managed key will be used for catalog. For user-defined sharding type, if encryptionKeyDetails are not provided for any shard or catalog, then Oracle managed key will be used for such shard or catalog. For system-defined or user-defined sharding type, if the shard or catalog has a peer in region other than primary shard or catalog region, then make sure to provide virtual vault for such shard or catalog, which is also replicated to peer region (the region where peer or standby shard or catalog exists).
        /// </summary>
        public readonly Outputs.ShardedDatabaseCatalogDetailEncryptionKeyDetails? EncryptionKeyDetails;
        /// <summary>
        /// Determines the auto-scaling mode for the catalog database.
        /// </summary>
        public readonly bool IsAutoScalingEnabled;
        /// <summary>
        /// Additional metadata related to shard's underlying supporting resource.
        /// </summary>
        public readonly ImmutableDictionary<string, string>? Metadata;
        /// <summary>
        /// Name of the shard.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer cloud Autonomous Exadata VM Cluster.
        /// </summary>
        public readonly string? PeerCloudAutonomousVmClusterId;
        /// <summary>
        /// Name of the shard-group to which the shard belongs.
        /// </summary>
        public readonly string? ShardGroup;
        /// <summary>
        /// Status of shard or catalog or gsm for the sharded database.
        /// </summary>
        public readonly string? Status;
        /// <summary>
        /// Identifier of the underlying supporting resource.
        /// </summary>
        public readonly string? SupportingResourceId;
        /// <summary>
        /// The time the the Sharded Database was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The time the ssl certificate associated with shard expires. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string? TimeSslCertificateExpires;
        /// <summary>
        /// The time the Sharded Database was last updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private ShardedDatabaseCatalogDetail(
            string adminPassword,

            string cloudAutonomousVmClusterId,

            double computeCount,

            string? containerDatabaseId,

            string? containerDatabaseParentId,

            double dataStorageSizeInGbs,

            Outputs.ShardedDatabaseCatalogDetailEncryptionKeyDetails? encryptionKeyDetails,

            bool isAutoScalingEnabled,

            ImmutableDictionary<string, string>? metadata,

            string? name,

            string? peerCloudAutonomousVmClusterId,

            string? shardGroup,

            string? status,

            string? supportingResourceId,

            string? timeCreated,

            string? timeSslCertificateExpires,

            string? timeUpdated)
        {
            AdminPassword = adminPassword;
            CloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            ComputeCount = computeCount;
            ContainerDatabaseId = containerDatabaseId;
            ContainerDatabaseParentId = containerDatabaseParentId;
            DataStorageSizeInGbs = dataStorageSizeInGbs;
            EncryptionKeyDetails = encryptionKeyDetails;
            IsAutoScalingEnabled = isAutoScalingEnabled;
            Metadata = metadata;
            Name = name;
            PeerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            ShardGroup = shardGroup;
            Status = status;
            SupportingResourceId = supportingResourceId;
            TimeCreated = timeCreated;
            TimeSslCertificateExpires = timeSslCertificateExpires;
            TimeUpdated = timeUpdated;
        }
    }
}
