// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetNodePool
    {
        /// <summary>
        /// This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the details of a node pool.
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
        ///     var testNodePool = Oci.ContainerEngine.GetNodePool.Invoke(new()
        ///     {
        ///         NodePoolId = testNodePoolOciContainerengineNodePool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNodePoolResult> InvokeAsync(GetNodePoolArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNodePoolResult>("oci:ContainerEngine/getNodePool:getNodePool", args ?? new GetNodePoolArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the details of a node pool.
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
        ///     var testNodePool = Oci.ContainerEngine.GetNodePool.Invoke(new()
        ///     {
        ///         NodePoolId = testNodePoolOciContainerengineNodePool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNodePoolResult> Invoke(GetNodePoolInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNodePoolResult>("oci:ContainerEngine/getNodePool:getNodePool", args ?? new GetNodePoolInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the details of a node pool.
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
        ///     var testNodePool = Oci.ContainerEngine.GetNodePool.Invoke(new()
        ///     {
        ///         NodePoolId = testNodePoolOciContainerengineNodePool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNodePoolResult> Invoke(GetNodePoolInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNodePoolResult>("oci:ContainerEngine/getNodePool:getNodePool", args ?? new GetNodePoolInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNodePoolArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the node pool.
        /// </summary>
        [Input("nodePoolId", required: true)]
        public string NodePoolId { get; set; } = null!;

        public GetNodePoolArgs()
        {
        }
        public static new GetNodePoolArgs Empty => new GetNodePoolArgs();
    }

    public sealed class GetNodePoolInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the node pool.
        /// </summary>
        [Input("nodePoolId", required: true)]
        public Input<string> NodePoolId { get; set; } = null!;

        public GetNodePoolInvokeArgs()
        {
        }
        public static new GetNodePoolInvokeArgs Empty => new GetNodePoolInvokeArgs();
    }


    [OutputType]
    public sealed class GetNodePoolResult
    {
        /// <summary>
        /// The OCID of the cluster to which this node pool is attached.
        /// </summary>
        public readonly string ClusterId;
        /// <summary>
        /// The OCID of the compartment in which the node pool exists.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the compute instance backing this node.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolInitialNodeLabelResult> InitialNodeLabels;
        /// <summary>
        /// The version of Kubernetes this node is running.
        /// </summary>
        public readonly string KubernetesVersion;
        /// <summary>
        /// Details about the state of the node.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The name of the node.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The configuration of nodes in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeConfigDetailResult> NodeConfigDetails;
        /// <summary>
        /// Node Eviction Details configuration
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeEvictionNodePoolSettingResult> NodeEvictionNodePoolSettings;
        /// <summary>
        /// Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        /// </summary>
        public readonly string NodeImageId;
        /// <summary>
        /// Deprecated. see `nodeSource`. The name of the image running on the nodes in the node pool.
        /// </summary>
        public readonly string NodeImageName;
        /// <summary>
        /// A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        /// </summary>
        public readonly ImmutableDictionary<string, string> NodeMetadata;
        /// <summary>
        /// Node Pool Cycling Details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodePoolCyclingDetailResult> NodePoolCyclingDetails;
        /// <summary>
        /// The OCID of the node pool to which this node belongs.
        /// </summary>
        public readonly string NodePoolId;
        /// <summary>
        /// The name of the node shape of the nodes in the node pool.
        /// </summary>
        public readonly string NodeShape;
        /// <summary>
        /// The shape configuration of the nodes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeShapeConfigResult> NodeShapeConfigs;
        /// <summary>
        /// Source running on the nodes in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeSourceDetailResult> NodeSourceDetails;
        /// <summary>
        /// Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeSourceResult> NodeSources;
        /// <summary>
        /// The nodes in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolNodeResult> Nodes;
        /// <summary>
        /// The number of nodes in each subnet.
        /// </summary>
        public readonly int QuantityPerSubnet;
        /// <summary>
        /// The SSH public key on each node in the node pool on launch.
        /// </summary>
        public readonly string SshPublicKey;
        /// <summary>
        /// The state of the nodepool.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCIDs of the subnets in which to place nodes for this node pool.
        /// </summary>
        public readonly ImmutableArray<string> SubnetIds;

        [OutputConstructor]
        private GetNodePoolResult(
            string clusterId,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetNodePoolInitialNodeLabelResult> initialNodeLabels,

            string kubernetesVersion,

            string lifecycleDetails,

            string name,

            ImmutableArray<Outputs.GetNodePoolNodeConfigDetailResult> nodeConfigDetails,

            ImmutableArray<Outputs.GetNodePoolNodeEvictionNodePoolSettingResult> nodeEvictionNodePoolSettings,

            string nodeImageId,

            string nodeImageName,

            ImmutableDictionary<string, string> nodeMetadata,

            ImmutableArray<Outputs.GetNodePoolNodePoolCyclingDetailResult> nodePoolCyclingDetails,

            string nodePoolId,

            string nodeShape,

            ImmutableArray<Outputs.GetNodePoolNodeShapeConfigResult> nodeShapeConfigs,

            ImmutableArray<Outputs.GetNodePoolNodeSourceDetailResult> nodeSourceDetails,

            ImmutableArray<Outputs.GetNodePoolNodeSourceResult> nodeSources,

            ImmutableArray<Outputs.GetNodePoolNodeResult> nodes,

            int quantityPerSubnet,

            string sshPublicKey,

            string state,

            ImmutableArray<string> subnetIds)
        {
            ClusterId = clusterId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            InitialNodeLabels = initialNodeLabels;
            KubernetesVersion = kubernetesVersion;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            NodeConfigDetails = nodeConfigDetails;
            NodeEvictionNodePoolSettings = nodeEvictionNodePoolSettings;
            NodeImageId = nodeImageId;
            NodeImageName = nodeImageName;
            NodeMetadata = nodeMetadata;
            NodePoolCyclingDetails = nodePoolCyclingDetails;
            NodePoolId = nodePoolId;
            NodeShape = nodeShape;
            NodeShapeConfigs = nodeShapeConfigs;
            NodeSourceDetails = nodeSourceDetails;
            NodeSources = nodeSources;
            Nodes = nodes;
            QuantityPerSubnet = quantityPerSubnet;
            SshPublicKey = sshPublicKey;
            State = state;
            SubnetIds = subnetIds;
        }
    }
}
