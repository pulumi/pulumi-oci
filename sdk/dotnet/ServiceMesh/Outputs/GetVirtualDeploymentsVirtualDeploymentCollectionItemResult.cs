// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Outputs
{

    [OutputType]
    public sealed class GetVirtualDeploymentsVirtualDeploymentCollectionItemResult
    {
        /// <summary>
        /// This configuration determines if logging is enabled and where the logs will be output.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemAccessLoggingResult> AccessLoggings;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Unique VirtualDeployment identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The listeners for the virtual deployment
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemListenerResult> Listeners;
        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Service Discovery configuration for virtual deployments.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemServiceDiscoveryResult> ServiceDiscoveries;
        /// <summary>
        /// A filter to return only resources that match the life cycle state given.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time when this resource was created in an RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when this resource was updated in an RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Unique VirtualService identifier.
        /// </summary>
        public readonly string VirtualServiceId;

        [OutputConstructor]
        private GetVirtualDeploymentsVirtualDeploymentCollectionItemResult(
            ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemAccessLoggingResult> accessLoggings,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemListenerResult> listeners,

            string name,

            ImmutableArray<Outputs.GetVirtualDeploymentsVirtualDeploymentCollectionItemServiceDiscoveryResult> serviceDiscoveries,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            string virtualServiceId)
        {
            AccessLoggings = accessLoggings;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Listeners = listeners;
            Name = name;
            ServiceDiscoveries = serviceDiscoveries;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            VirtualServiceId = virtualServiceId;
        }
    }
}