// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge
{
    public static class GetAssetSource
    {
        /// <summary>
        /// This data source provides details about a specific Asset Source resource in Oracle Cloud Infrastructure Cloud Bridge service.
        /// 
        /// Gets the asset source by ID.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAssetSource = Oci.CloudBridge.GetAssetSource.Invoke(new()
        ///     {
        ///         AssetSourceId = testAssetSourceOciCloudBridgeAssetSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAssetSourceResult> InvokeAsync(GetAssetSourceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAssetSourceResult>("oci:CloudBridge/getAssetSource:getAssetSource", args ?? new GetAssetSourceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Asset Source resource in Oracle Cloud Infrastructure Cloud Bridge service.
        /// 
        /// Gets the asset source by ID.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAssetSource = Oci.CloudBridge.GetAssetSource.Invoke(new()
        ///     {
        ///         AssetSourceId = testAssetSourceOciCloudBridgeAssetSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAssetSourceResult> Invoke(GetAssetSourceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAssetSourceResult>("oci:CloudBridge/getAssetSource:getAssetSource", args ?? new GetAssetSourceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Asset Source resource in Oracle Cloud Infrastructure Cloud Bridge service.
        /// 
        /// Gets the asset source by ID.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAssetSource = Oci.CloudBridge.GetAssetSource.Invoke(new()
        ///     {
        ///         AssetSourceId = testAssetSourceOciCloudBridgeAssetSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAssetSourceResult> Invoke(GetAssetSourceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAssetSourceResult>("oci:CloudBridge/getAssetSource:getAssetSource", args ?? new GetAssetSourceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAssetSourceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
        /// </summary>
        [Input("assetSourceId", required: true)]
        public string AssetSourceId { get; set; } = null!;

        public GetAssetSourceArgs()
        {
        }
        public static new GetAssetSourceArgs Empty => new GetAssetSourceArgs();
    }

    public sealed class GetAssetSourceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
        /// </summary>
        [Input("assetSourceId", required: true)]
        public Input<string> AssetSourceId { get; set; } = null!;

        public GetAssetSourceInvokeArgs()
        {
        }
        public static new GetAssetSourceInvokeArgs Empty => new GetAssetSourceInvokeArgs();
    }


    [OutputType]
    public sealed class GetAssetSourceResult
    {
        /// <summary>
        /// Flag indicating whether historical metrics are collected for assets, originating from this asset source.
        /// </summary>
        public readonly bool AreHistoricalMetricsCollected;
        /// <summary>
        /// Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
        /// </summary>
        public readonly bool AreRealtimeMetricsCollected;
        public readonly string AssetSourceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
        /// </summary>
        public readonly string AssetsCompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the resource.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Credentials for an asset source.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAssetSourceDiscoveryCredentialResult> DiscoveryCredentials;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
        /// </summary>
        public readonly string DiscoveryScheduleId;
        /// <summary>
        /// A user-friendly name for the asset source. Does not have to be unique, and it's mutable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
        /// </summary>
        public readonly string EnvironmentId;
        /// <summary>
        /// The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
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
        public readonly ImmutableArray<Outputs.GetAssetSourceReplicationCredentialResult> ReplicationCredentials;
        /// <summary>
        /// The current state of the asset source.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
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
        private GetAssetSourceResult(
            bool areHistoricalMetricsCollected,

            bool areRealtimeMetricsCollected,

            string assetSourceId,

            string assetsCompartmentId,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableArray<Outputs.GetAssetSourceDiscoveryCredentialResult> discoveryCredentials,

            string discoveryScheduleId,

            string displayName,

            string environmentId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string inventoryId,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetAssetSourceReplicationCredentialResult> replicationCredentials,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string type,

            string vcenterEndpoint)
        {
            AreHistoricalMetricsCollected = areHistoricalMetricsCollected;
            AreRealtimeMetricsCollected = areRealtimeMetricsCollected;
            AssetSourceId = assetSourceId;
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
