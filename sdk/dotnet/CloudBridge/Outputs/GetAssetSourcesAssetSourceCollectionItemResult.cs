// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class GetAssetSourcesAssetSourceCollectionItemResult
    {
        /// <summary>
        /// Flag indicating whether historical metrics are collected for assets, originating from this asset source.
        /// </summary>
        public readonly bool AreHistoricalMetricsCollected;
        /// <summary>
        /// Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
        /// </summary>
        public readonly bool AreRealtimeMetricsCollected;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
        /// </summary>
        public readonly string AssetsCompartmentId;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Credentials for an asset source.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemDiscoveryCredentialResult> DiscoveryCredentials;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
        /// </summary>
        public readonly string DiscoveryScheduleId;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
        /// </summary>
        public readonly string EnvironmentId;
        /// <summary>
        /// The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the inventory that will contain created assets.
        /// </summary>
        public readonly string InventoryId;
        /// <summary>
        /// The detailed state of the asset source.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Credentials for an asset source.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemReplicationCredentialResult> ReplicationCredentials;
        /// <summary>
        /// The current state of the asset source.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time when the asset source was created in the RFC3339 format.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The point in time that the asset source was last updated in the RFC3339 format.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The type of asset source. Indicates external origin of the assets that are read by assigning this asset source.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Endpoint for VMware asset discovery and replication in the form of ```https://&lt;host&gt;:&lt;port&gt;/sdk```
        /// </summary>
        public readonly string VcenterEndpoint;

        [OutputConstructor]
        private GetAssetSourcesAssetSourceCollectionItemResult(
            bool areHistoricalMetricsCollected,

            bool areRealtimeMetricsCollected,

            string assetsCompartmentId,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemDiscoveryCredentialResult> discoveryCredentials,

            string discoveryScheduleId,

            string displayName,

            string environmentId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string inventoryId,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemReplicationCredentialResult> replicationCredentials,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            string type,

            string vcenterEndpoint)
        {
            AreHistoricalMetricsCollected = areHistoricalMetricsCollected;
            AreRealtimeMetricsCollected = areRealtimeMetricsCollected;
            AssetsCompartmentId = assetsCompartmentId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DiscoveryCredentials = discoveryCredentials;
            DiscoveryScheduleId = discoveryScheduleId;
            DisplayName = displayName;
            EnvironmentId = environmentId;
            FreeformTags = freeformTags;
            Id = id;
            InventoryId = inventoryId;
            LifecycleDetails = lifecycleDetails;
            ReplicationCredentials = replicationCredentials;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            VcenterEndpoint = vcenterEndpoint;
        }
    }
}