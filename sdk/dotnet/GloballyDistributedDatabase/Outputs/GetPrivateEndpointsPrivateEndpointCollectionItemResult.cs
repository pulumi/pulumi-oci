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
    public sealed class GetPrivateEndpointsPrivateEndpointCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// PrivateEndpoint description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only private endpoint that match the entire name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The identifier of the Private Endpoint.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Detailed message for the lifecycle state.
        /// </summary>
        public readonly string LifecycleStateDetails;
        /// <summary>
        /// The OCIDs of the network security groups that the private endpoint belongs to.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// IP address of the Private Endpoint.
        /// </summary>
        public readonly string PrivateIp;
        /// <summary>
        /// The identifier of the proxy compute instance.
        /// </summary>
        public readonly string ProxyComputeInstanceId;
        public readonly int ReinstateProxyInstanceTrigger;
        /// <summary>
        /// The OCIDs of sharded databases that consumes the given private endpoint.
        /// </summary>
        public readonly ImmutableArray<string> ShardedDatabases;
        /// <summary>
        /// A filter to return only resources their lifecycleState matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Identifier of the subnet in which private endpoint exists.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the PrivateEndpoint was first created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the Private Endpoint was last updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Identifier of the VCN in which subnet exists.
        /// </summary>
        public readonly string VcnId;

        [OutputConstructor]
        private GetPrivateEndpointsPrivateEndpointCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleStateDetails,

            ImmutableArray<string> nsgIds,

            string privateIp,

            string proxyComputeInstanceId,

            int reinstateProxyInstanceTrigger,

            ImmutableArray<string> shardedDatabases,

            string state,

            string subnetId,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string vcnId)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleStateDetails = lifecycleStateDetails;
            NsgIds = nsgIds;
            PrivateIp = privateIp;
            ProxyComputeInstanceId = proxyComputeInstanceId;
            ReinstateProxyInstanceTrigger = reinstateProxyInstanceTrigger;
            ShardedDatabases = shardedDatabases;
            State = state;
            SubnetId = subnetId;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            VcnId = vcnId;
        }
    }
}
