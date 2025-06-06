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
    public sealed class GetNodePoolNodeConfigDetailResult
    {
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Whether to enable in-transit encryption for the data volume's paravirtualized attachment. This field applies to both block volumes and boot volumes. The default value is false.
        /// </summary>
        public readonly bool IsPvEncryptionInTransitEnabled;
        /// <summary>
        /// The OCID of the Key Management Service key assigned to the boot volume.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The CNI related configuration of pods in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeConfigDetailNodePoolPodNetworkOptionDetailResult> NodePoolPodNetworkOptionDetails;
        /// <summary>
        /// The OCIDs of the Network Security Group(s) to associate nodes for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The placement configurations for the node pool. Provide one placement configuration for each availability domain in which you intend to launch a node.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeConfigDetailPlacementConfigResult> PlacementConfigs;
        /// <summary>
        /// The number of nodes in the node pool.
        /// </summary>
        public readonly int Size;

        [OutputConstructor]
        private GetNodePoolNodeConfigDetailResult(
            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            bool isPvEncryptionInTransitEnabled,

            string kmsKeyId,

            ImmutableArray<Outputs.GetNodePoolNodeConfigDetailNodePoolPodNetworkOptionDetailResult> nodePoolPodNetworkOptionDetails,

            ImmutableArray<string> nsgIds,

            ImmutableArray<Outputs.GetNodePoolNodeConfigDetailPlacementConfigResult> placementConfigs,

            int size)
        {
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            IsPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            KmsKeyId = kmsKeyId;
            NodePoolPodNetworkOptionDetails = nodePoolPodNetworkOptionDetails;
            NsgIds = nsgIds;
            PlacementConfigs = placementConfigs;
            Size = size;
        }
    }
}
