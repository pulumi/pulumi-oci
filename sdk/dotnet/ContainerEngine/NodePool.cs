// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    /// <summary>
    /// This resource provides the Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
    /// 
    /// Create a new node pool.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testNodePool = new Oci.ContainerEngine.NodePool("testNodePool", new Oci.ContainerEngine.NodePoolArgs
    ///         {
    ///             ClusterId = oci_containerengine_cluster.Test_cluster.Id,
    ///             CompartmentId = @var.Compartment_id,
    ///             KubernetesVersion = @var.Node_pool_kubernetes_version,
    ///             NodeShape = @var.Node_pool_node_shape,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             InitialNodeLabels = 
    ///             {
    ///                 new Oci.ContainerEngine.Inputs.NodePoolInitialNodeLabelArgs
    ///                 {
    ///                     Key = @var.Node_pool_initial_node_labels_key,
    ///                     Value = @var.Node_pool_initial_node_labels_value,
    ///                 },
    ///             },
    ///             NodeConfigDetails = new Oci.ContainerEngine.Inputs.NodePoolNodeConfigDetailsArgs
    ///             {
    ///                 PlacementConfigs = 
    ///                 {
    ///                     new Oci.ContainerEngine.Inputs.NodePoolNodeConfigDetailsPlacementConfigArgs
    ///                     {
    ///                         AvailabilityDomain = @var.Node_pool_node_config_details_placement_configs_availability_domain,
    ///                         SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                         CapacityReservationId = oci_containerengine_capacity_reservation.Test_capacity_reservation.Id,
    ///                     },
    ///                 },
    ///                 Size = @var.Node_pool_node_config_details_size,
    ///                 IsPvEncryptionInTransitEnabled = @var.Node_pool_node_config_details_is_pv_encryption_in_transit_enabled,
    ///                 KmsKeyId = oci_kms_key.Test_key.Id,
    ///                 DefinedTags = 
    ///                 {
    ///                     { "Operations.CostCenter", "42" },
    ///                 },
    ///                 FreeformTags = 
    ///                 {
    ///                     { "Department", "Finance" },
    ///                 },
    ///                 NsgIds = @var.Node_pool_node_config_details_nsg_ids,
    ///             },
    ///             NodeImageName = oci_core_image.Test_image.Name,
    ///             NodeMetadata = @var.Node_pool_node_metadata,
    ///             NodeShapeConfig = new Oci.ContainerEngine.Inputs.NodePoolNodeShapeConfigArgs
    ///             {
    ///                 MemoryInGbs = @var.Node_pool_node_shape_config_memory_in_gbs,
    ///                 Ocpus = @var.Node_pool_node_shape_config_ocpus,
    ///             },
    ///             NodeSourceDetails = new Oci.ContainerEngine.Inputs.NodePoolNodeSourceDetailsArgs
    ///             {
    ///                 ImageId = oci_core_image.Test_image.Id,
    ///                 SourceType = @var.Node_pool_node_source_details_source_type,
    ///                 BootVolumeSizeInGbs = @var.Node_pool_node_source_details_boot_volume_size_in_gbs,
    ///             },
    ///             QuantityPerSubnet = @var.Node_pool_quantity_per_subnet,
    ///             SshPublicKey = @var.Node_pool_ssh_public_key,
    ///             SubnetIds = @var.Node_pool_subnet_ids,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// NodePools can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:ContainerEngine/nodePool:NodePool test_node_pool "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:ContainerEngine/nodePool:NodePool")]
    public partial class NodePool : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the cluster to which this node pool is attached.
        /// </summary>
        [Output("clusterId")]
        public Output<string> ClusterId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the compartment in which the node pool exists.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        /// </summary>
        [Output("initialNodeLabels")]
        public Output<ImmutableArray<Outputs.NodePoolInitialNodeLabel>> InitialNodeLabels { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The version of Kubernetes to install on the nodes in the node pool.
        /// </summary>
        [Output("kubernetesVersion")]
        public Output<string> KubernetesVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the node pool. Avoid entering confidential information.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The configuration of nodes in the node pool. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        [Output("nodeConfigDetails")]
        public Output<Outputs.NodePoolNodeConfigDetails> NodeConfigDetails { get; private set; } = null!;

        /// <summary>
        /// Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        /// </summary>
        [Output("nodeImageId")]
        public Output<string> NodeImageId { get; private set; } = null!;

        /// <summary>
        /// Deprecated. Use `nodeSourceDetails` instead. If you specify values for both, this value is ignored. The name of the image running on the nodes in the node pool. Cannot be used when `node_image_id` is specified.
        /// </summary>
        [Output("nodeImageName")]
        public Output<string> NodeImageName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        /// </summary>
        [Output("nodeMetadata")]
        public Output<ImmutableDictionary<string, object>> NodeMetadata { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the node shape of the nodes in the node pool.
        /// </summary>
        [Output("nodeShape")]
        public Output<string> NodeShape { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specify the configuration of the shape to launch nodes in the node pool.
        /// </summary>
        [Output("nodeShapeConfig")]
        public Output<Outputs.NodePoolNodeShapeConfig> NodeShapeConfig { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specify the source to use to launch nodes in the node pool. Currently, image is the only supported source.
        /// </summary>
        [Output("nodeSourceDetails")]
        public Output<Outputs.NodePoolNodeSourceDetails> NodeSourceDetails { get; private set; } = null!;

        /// <summary>
        /// Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
        /// </summary>
        [Output("nodeSources")]
        public Output<ImmutableArray<Outputs.NodePoolNodeSource>> NodeSources { get; private set; } = null!;

        /// <summary>
        /// The nodes in the node pool.
        /// </summary>
        [Output("nodes")]
        public Output<ImmutableArray<Outputs.NodePoolNode>> Nodes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Optional, default to 1. The number of nodes to create in each subnet specified in subnetIds property. When used, subnetIds is required. This property is deprecated, use nodeConfigDetails instead.
        /// </summary>
        [Output("quantityPerSubnet")]
        public Output<int> QuantityPerSubnet { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The SSH public key on each node in the node pool on launch.
        /// </summary>
        [Output("sshPublicKey")]
        public Output<string> SshPublicKey { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCIDs of the subnets in which to place nodes for this node pool. When used, quantityPerSubnet can be provided. This property is deprecated, use nodeConfigDetails. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        [Output("subnetIds")]
        public Output<ImmutableArray<string>> SubnetIds { get; private set; } = null!;


        /// <summary>
        /// Create a NodePool resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NodePool(string name, NodePoolArgs args, CustomResourceOptions? options = null)
            : base("oci:ContainerEngine/nodePool:NodePool", name, args ?? new NodePoolArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NodePool(string name, Input<string> id, NodePoolState? state = null, CustomResourceOptions? options = null)
            : base("oci:ContainerEngine/nodePool:NodePool", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing NodePool resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NodePool Get(string name, Input<string> id, NodePoolState? state = null, CustomResourceOptions? options = null)
        {
            return new NodePool(name, id, state, options);
        }
    }

    public sealed class NodePoolArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the cluster to which this node pool is attached.
        /// </summary>
        [Input("clusterId", required: true)]
        public Input<string> ClusterId { get; set; } = null!;

        /// <summary>
        /// The OCID of the compartment in which the node pool exists.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("initialNodeLabels")]
        private InputList<Inputs.NodePoolInitialNodeLabelArgs>? _initialNodeLabels;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        /// </summary>
        public InputList<Inputs.NodePoolInitialNodeLabelArgs> InitialNodeLabels
        {
            get => _initialNodeLabels ?? (_initialNodeLabels = new InputList<Inputs.NodePoolInitialNodeLabelArgs>());
            set => _initialNodeLabels = value;
        }

        /// <summary>
        /// (Updatable) The version of Kubernetes to install on the nodes in the node pool.
        /// </summary>
        [Input("kubernetesVersion", required: true)]
        public Input<string> KubernetesVersion { get; set; } = null!;

        /// <summary>
        /// (Updatable) The name of the node pool. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The configuration of nodes in the node pool. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        [Input("nodeConfigDetails")]
        public Input<Inputs.NodePoolNodeConfigDetailsArgs>? NodeConfigDetails { get; set; }

        /// <summary>
        /// Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        /// </summary>
        [Input("nodeImageId")]
        public Input<string>? NodeImageId { get; set; }

        /// <summary>
        /// Deprecated. Use `nodeSourceDetails` instead. If you specify values for both, this value is ignored. The name of the image running on the nodes in the node pool. Cannot be used when `node_image_id` is specified.
        /// </summary>
        [Input("nodeImageName")]
        public Input<string>? NodeImageName { get; set; }

        [Input("nodeMetadata")]
        private InputMap<object>? _nodeMetadata;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        /// </summary>
        public InputMap<object> NodeMetadata
        {
            get => _nodeMetadata ?? (_nodeMetadata = new InputMap<object>());
            set => _nodeMetadata = value;
        }

        /// <summary>
        /// (Updatable) The name of the node shape of the nodes in the node pool.
        /// </summary>
        [Input("nodeShape", required: true)]
        public Input<string> NodeShape { get; set; } = null!;

        /// <summary>
        /// (Updatable) Specify the configuration of the shape to launch nodes in the node pool.
        /// </summary>
        [Input("nodeShapeConfig")]
        public Input<Inputs.NodePoolNodeShapeConfigArgs>? NodeShapeConfig { get; set; }

        /// <summary>
        /// (Updatable) Specify the source to use to launch nodes in the node pool. Currently, image is the only supported source.
        /// </summary>
        [Input("nodeSourceDetails")]
        public Input<Inputs.NodePoolNodeSourceDetailsArgs>? NodeSourceDetails { get; set; }

        /// <summary>
        /// (Updatable) Optional, default to 1. The number of nodes to create in each subnet specified in subnetIds property. When used, subnetIds is required. This property is deprecated, use nodeConfigDetails instead.
        /// </summary>
        [Input("quantityPerSubnet")]
        public Input<int>? QuantityPerSubnet { get; set; }

        /// <summary>
        /// (Updatable) The SSH public key on each node in the node pool on launch.
        /// </summary>
        [Input("sshPublicKey")]
        public Input<string>? SshPublicKey { get; set; }

        [Input("subnetIds")]
        private InputList<string>? _subnetIds;

        /// <summary>
        /// (Updatable) The OCIDs of the subnets in which to place nodes for this node pool. When used, quantityPerSubnet can be provided. This property is deprecated, use nodeConfigDetails. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        public InputList<string> SubnetIds
        {
            get => _subnetIds ?? (_subnetIds = new InputList<string>());
            set => _subnetIds = value;
        }

        public NodePoolArgs()
        {
        }
    }

    public sealed class NodePoolState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the cluster to which this node pool is attached.
        /// </summary>
        [Input("clusterId")]
        public Input<string>? ClusterId { get; set; }

        /// <summary>
        /// The OCID of the compartment in which the node pool exists.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("initialNodeLabels")]
        private InputList<Inputs.NodePoolInitialNodeLabelGetArgs>? _initialNodeLabels;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        /// </summary>
        public InputList<Inputs.NodePoolInitialNodeLabelGetArgs> InitialNodeLabels
        {
            get => _initialNodeLabels ?? (_initialNodeLabels = new InputList<Inputs.NodePoolInitialNodeLabelGetArgs>());
            set => _initialNodeLabels = value;
        }

        /// <summary>
        /// (Updatable) The version of Kubernetes to install on the nodes in the node pool.
        /// </summary>
        [Input("kubernetesVersion")]
        public Input<string>? KubernetesVersion { get; set; }

        /// <summary>
        /// (Updatable) The name of the node pool. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The configuration of nodes in the node pool. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        [Input("nodeConfigDetails")]
        public Input<Inputs.NodePoolNodeConfigDetailsGetArgs>? NodeConfigDetails { get; set; }

        /// <summary>
        /// Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        /// </summary>
        [Input("nodeImageId")]
        public Input<string>? NodeImageId { get; set; }

        /// <summary>
        /// Deprecated. Use `nodeSourceDetails` instead. If you specify values for both, this value is ignored. The name of the image running on the nodes in the node pool. Cannot be used when `node_image_id` is specified.
        /// </summary>
        [Input("nodeImageName")]
        public Input<string>? NodeImageName { get; set; }

        [Input("nodeMetadata")]
        private InputMap<object>? _nodeMetadata;

        /// <summary>
        /// (Updatable) A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        /// </summary>
        public InputMap<object> NodeMetadata
        {
            get => _nodeMetadata ?? (_nodeMetadata = new InputMap<object>());
            set => _nodeMetadata = value;
        }

        /// <summary>
        /// (Updatable) The name of the node shape of the nodes in the node pool.
        /// </summary>
        [Input("nodeShape")]
        public Input<string>? NodeShape { get; set; }

        /// <summary>
        /// (Updatable) Specify the configuration of the shape to launch nodes in the node pool.
        /// </summary>
        [Input("nodeShapeConfig")]
        public Input<Inputs.NodePoolNodeShapeConfigGetArgs>? NodeShapeConfig { get; set; }

        /// <summary>
        /// (Updatable) Specify the source to use to launch nodes in the node pool. Currently, image is the only supported source.
        /// </summary>
        [Input("nodeSourceDetails")]
        public Input<Inputs.NodePoolNodeSourceDetailsGetArgs>? NodeSourceDetails { get; set; }

        [Input("nodeSources")]
        private InputList<Inputs.NodePoolNodeSourceGetArgs>? _nodeSources;

        /// <summary>
        /// Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
        /// </summary>
        public InputList<Inputs.NodePoolNodeSourceGetArgs> NodeSources
        {
            get => _nodeSources ?? (_nodeSources = new InputList<Inputs.NodePoolNodeSourceGetArgs>());
            set => _nodeSources = value;
        }

        [Input("nodes")]
        private InputList<Inputs.NodePoolNodeGetArgs>? _nodes;

        /// <summary>
        /// The nodes in the node pool.
        /// </summary>
        public InputList<Inputs.NodePoolNodeGetArgs> Nodes
        {
            get => _nodes ?? (_nodes = new InputList<Inputs.NodePoolNodeGetArgs>());
            set => _nodes = value;
        }

        /// <summary>
        /// (Updatable) Optional, default to 1. The number of nodes to create in each subnet specified in subnetIds property. When used, subnetIds is required. This property is deprecated, use nodeConfigDetails instead.
        /// </summary>
        [Input("quantityPerSubnet")]
        public Input<int>? QuantityPerSubnet { get; set; }

        /// <summary>
        /// (Updatable) The SSH public key on each node in the node pool on launch.
        /// </summary>
        [Input("sshPublicKey")]
        public Input<string>? SshPublicKey { get; set; }

        [Input("subnetIds")]
        private InputList<string>? _subnetIds;

        /// <summary>
        /// (Updatable) The OCIDs of the subnets in which to place nodes for this node pool. When used, quantityPerSubnet can be provided. This property is deprecated, use nodeConfigDetails. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
        /// </summary>
        public InputList<string> SubnetIds
        {
            get => _subnetIds ?? (_subnetIds = new InputList<string>());
            set => _subnetIds = value;
        }

        public NodePoolState()
        {
        }
    }
}
