// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetVirtualNodePoolsVirtualNodePoolResult
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        public readonly string ClusterId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Display name of the virtual node pool. This is a non-unique value.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the virtual node pool.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Initial labels that will be added to the Kubernetes Virtual Node object when it registers. This is the same as virtualNodePool resources.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolInitialVirtualNodeLabelResult> InitialVirtualNodeLabels;
        /// <summary>
        /// The version of Kubernetes running on the nodes in the node pool.
        /// </summary>
        public readonly string KubernetesVersion;
        /// <summary>
        /// Details about the state of the Virtual Node Pool.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// List of network security group IDs applied to the Pod VNIC.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The list of placement configurations which determines where Virtual Nodes will be provisioned across as it relates to the subnet and availability domains. The size attribute determines how many we evenly spread across these placement configurations
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolPlacementConfigurationResult> PlacementConfigurations;
        /// <summary>
        /// The pod configuration for pods run on virtual nodes of this virtual node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolPodConfigurationResult> PodConfigurations;
        /// <summary>
        /// The number of Virtual Nodes that should be in the Virtual Node Pool. The placement configurations determine where these virtual nodes are placed.
        /// </summary>
        public readonly int Size;
        /// <summary>
        /// A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// A taint is a collection of &lt;key, value, effect&gt;. These taints will be applied to the Virtual Nodes of this Virtual Node Pool for Kubernetes scheduling.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolTaintResult> Taints;
        /// <summary>
        /// The time the virtual node pool was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the virtual node pool was updated.
        /// </summary>
        public readonly string TimeUpdated;
        public readonly string VirtualNodePoolId;
        /// <summary>
        /// The tags associated to the virtual nodes in this virtual node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolVirtualNodeTagResult> VirtualNodeTags;

        [OutputConstructor]
        private GetVirtualNodePoolsVirtualNodePoolResult(
            string clusterId,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolInitialVirtualNodeLabelResult> initialVirtualNodeLabels,

            string kubernetesVersion,

            string lifecycleDetails,

            ImmutableArray<string> nsgIds,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolPlacementConfigurationResult> placementConfigurations,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolPodConfigurationResult> podConfigurations,

            int size,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolTaintResult> taints,

            string timeCreated,

            string timeUpdated,

            string virtualNodePoolId,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolVirtualNodeTagResult> virtualNodeTags)
        {
            ClusterId = clusterId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InitialVirtualNodeLabels = initialVirtualNodeLabels;
            KubernetesVersion = kubernetesVersion;
            LifecycleDetails = lifecycleDetails;
            NsgIds = nsgIds;
            PlacementConfigurations = placementConfigurations;
            PodConfigurations = podConfigurations;
            Size = size;
            State = state;
            SystemTags = systemTags;
            Taints = taints;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            VirtualNodePoolId = virtualNodePoolId;
            VirtualNodeTags = virtualNodeTags;
        }
    }
}
