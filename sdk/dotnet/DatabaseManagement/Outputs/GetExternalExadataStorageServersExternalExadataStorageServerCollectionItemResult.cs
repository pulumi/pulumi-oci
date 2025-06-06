// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalExadataStorageServersExternalExadataStorageServerCollectionItemResult
    {
        /// <summary>
        /// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> AdditionalDetails;
        public readonly string ConnectorId;
        /// <summary>
        /// The CPU count of the Exadata storage server.
        /// </summary>
        public readonly double CpuCount;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The optional single value query filter parameter on the entity display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        public readonly string ExadataInfrastructureId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The internal ID of the Exadata resource.
        /// </summary>
        public readonly string InternalId;
        /// <summary>
        /// The IP address of the Exadata storage server.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// The details of the lifecycle state of the Exadata resource.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The make model of the Exadata storage server.
        /// </summary>
        public readonly string MakeModel;
        /// <summary>
        /// The maximum flash disk IO operations per second of the Exadata storage server.
        /// </summary>
        public readonly int MaxFlashDiskIops;
        /// <summary>
        /// The maximum flash disk IO throughput in MB/s of the Exadata storage server.
        /// </summary>
        public readonly int MaxFlashDiskThroughput;
        /// <summary>
        /// The maximum hard disk IO operations per second of the Exadata storage server.
        /// </summary>
        public readonly int MaxHardDiskIops;
        /// <summary>
        /// The maximum hard disk IO throughput in MB/s of the Exadata storage server.
        /// </summary>
        public readonly int MaxHardDiskThroughput;
        /// <summary>
        /// The Exadata storage server memory size in GB.
        /// </summary>
        public readonly double MemoryGb;
        /// <summary>
        /// The type of Exadata resource.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// The current lifecycle state of the database resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The status of the Exadata resource.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server grid.
        /// </summary>
        public readonly string StorageGridId;
        /// <summary>
        /// The timestamp of the creation of the Exadata resource.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The timestamp of the last update of the Exadata resource.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The version of the Exadata resource.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetExternalExadataStorageServersExternalExadataStorageServerCollectionItemResult(
            ImmutableDictionary<string, string> additionalDetails,

            string connectorId,

            double cpuCount,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string exadataInfrastructureId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string internalId,

            string ipAddress,

            string lifecycleDetails,

            string makeModel,

            int maxFlashDiskIops,

            int maxFlashDiskThroughput,

            int maxHardDiskIops,

            int maxHardDiskThroughput,

            double memoryGb,

            string resourceType,

            string state,

            string status,

            string storageGridId,

            string timeCreated,

            string timeUpdated,

            string version)
        {
            AdditionalDetails = additionalDetails;
            ConnectorId = connectorId;
            CpuCount = cpuCount;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExadataInfrastructureId = exadataInfrastructureId;
            FreeformTags = freeformTags;
            Id = id;
            InternalId = internalId;
            IpAddress = ipAddress;
            LifecycleDetails = lifecycleDetails;
            MakeModel = makeModel;
            MaxFlashDiskIops = maxFlashDiskIops;
            MaxFlashDiskThroughput = maxFlashDiskThroughput;
            MaxHardDiskIops = maxHardDiskIops;
            MaxHardDiskThroughput = maxHardDiskThroughput;
            MemoryGb = memoryGb;
            ResourceType = resourceType;
            State = state;
            Status = status;
            StorageGridId = storageGridId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Version = version;
        }
    }
}
