// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService
{
    /// <summary>
    /// This resource provides the Bds Instance resource in Oracle Cloud Infrastructure Big Data Service service.
    /// 
    /// Creates a Big Data Service cluster.
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
    ///         var testBdsInstance = new Oci.BigDataService.BdsInstance("testBdsInstance", new Oci.BigDataService.BdsInstanceArgs
    ///         {
    ///             ClusterAdminPassword = @var.Bds_instance_cluster_admin_password,
    ///             ClusterPublicKey = @var.Bds_instance_cluster_public_key,
    ///             ClusterVersion = @var.Bds_instance_cluster_version,
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Bds_instance_display_name,
    ///             IsHighAvailability = @var.Bds_instance_is_high_availability,
    ///             IsSecure = @var.Bds_instance_is_secure,
    ///             MasterNode = new Oci.BigDataService.Inputs.BdsInstanceMasterNodeArgs
    ///             {
    ///                 Shape = @var.Bds_instance_nodes_shape,
    ///                 SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                 BlockVolumeSizeInGbs = @var.Bds_instance_nodes_block_volume_size_in_gbs,
    ///                 NumberOfNodes = @var.Bds_instance_number_of_nodes,
    ///             },
    ///             UtilNode = new Oci.BigDataService.Inputs.BdsInstanceUtilNodeArgs
    ///             {
    ///                 Shape = @var.Bds_instance_nodes_shape,
    ///                 SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                 BlockVolumeSizeInGbs = @var.Bds_instance_nodes_block_volume_size_in_gbs,
    ///                 NumberOfNodes = @var.Bds_instance_number_of_nodes,
    ///             },
    ///             WorkerNode = new Oci.BigDataService.Inputs.BdsInstanceWorkerNodeArgs
    ///             {
    ///                 Shape = @var.Bds_instance_nodes_shape,
    ///                 SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                 BlockVolumeSizeInGbs = @var.Bds_instance_nodes_block_volume_size_in_gbs,
    ///                 NumberOfNodes = @var.Bds_instance_number_of_nodes,
    ///             },
    ///             DefinedTags = @var.Bds_instance_defined_tags,
    ///             FreeformTags = @var.Bds_instance_freeform_tags,
    ///             NetworkConfig = new Oci.BigDataService.Inputs.BdsInstanceNetworkConfigArgs
    ///             {
    ///                 CidrBlock = @var.Bds_instance_network_config_cidr_block,
    ///                 IsNatGatewayRequired = @var.Bds_instance_network_config_is_nat_gateway_required,
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// BdsInstances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:BigDataService/bdsInstance:BdsInstance test_bds_instance "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:BigDataService/bdsInstance:BdsInstance")]
    public partial class BdsInstance : Pulumi.CustomResource
    {
        /// <summary>
        /// The information about added Cloud SQL capability
        /// </summary>
        [Output("cloudSqlDetails")]
        public Output<ImmutableArray<Outputs.BdsInstanceCloudSqlDetail>> CloudSqlDetails { get; private set; } = null!;

        /// <summary>
        /// Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
        /// </summary>
        [Output("clusterAdminPassword")]
        public Output<string> ClusterAdminPassword { get; private set; } = null!;

        /// <summary>
        /// Specific info about a Hadoop cluster
        /// </summary>
        [Output("clusterDetails")]
        public Output<ImmutableArray<Outputs.BdsInstanceClusterDetail>> ClusterDetails { get; private set; } = null!;

        /// <summary>
        /// The SSH public key used to authenticate the cluster connection.
        /// </summary>
        [Output("clusterPublicKey")]
        public Output<string> ClusterPublicKey { get; private set; } = null!;

        /// <summary>
        /// Version of the Hadoop distribution.
        /// </summary>
        [Output("clusterVersion")]
        public Output<string> ClusterVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The user who created the cluster.
        /// </summary>
        [Output("createdBy")]
        public Output<string> CreatedBy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example, `{"foo-namespace": {"bar-key": "value"}}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Name of the Big Data Service cluster.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. For example, `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Boolean flag specifying whether or not Cloud SQL should be configured.
        /// </summary>
        [Output("isCloudSqlConfigured")]
        public Output<bool> IsCloudSqlConfigured { get; private set; } = null!;

        /// <summary>
        /// Boolean flag specifying whether or not the cluster is highly available (HA).
        /// </summary>
        [Output("isHighAvailability")]
        public Output<bool> IsHighAvailability { get; private set; } = null!;

        /// <summary>
        /// Boolean flag specifying whether or not the cluster should be set up as secure.
        /// </summary>
        [Output("isSecure")]
        public Output<bool> IsSecure { get; private set; } = null!;

        [Output("masterNode")]
        public Output<Outputs.BdsInstanceMasterNode> MasterNode { get; private set; } = null!;

        /// <summary>
        /// Additional configuration of the user's network.
        /// </summary>
        [Output("networkConfig")]
        public Output<Outputs.BdsInstanceNetworkConfig> NetworkConfig { get; private set; } = null!;

        /// <summary>
        /// The list of nodes in the Big Data Service cluster.
        /// </summary>
        [Output("nodes")]
        public Output<ImmutableArray<Outputs.BdsInstanceNode>> Nodes { get; private set; } = null!;

        /// <summary>
        /// The number of nodes that form the cluster.
        /// </summary>
        [Output("numberOfNodes")]
        public Output<int> NumberOfNodes { get; private set; } = null!;

        /// <summary>
        /// The state of the cluster.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the cluster was updated, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        [Output("utilNode")]
        public Output<Outputs.BdsInstanceUtilNode> UtilNode { get; private set; } = null!;

        [Output("workerNode")]
        public Output<Outputs.BdsInstanceWorkerNode> WorkerNode { get; private set; } = null!;


        /// <summary>
        /// Create a BdsInstance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public BdsInstance(string name, BdsInstanceArgs args, CustomResourceOptions? options = null)
            : base("oci:BigDataService/bdsInstance:BdsInstance", name, args ?? new BdsInstanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private BdsInstance(string name, Input<string> id, BdsInstanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:BigDataService/bdsInstance:BdsInstance", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing BdsInstance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static BdsInstance Get(string name, Input<string> id, BdsInstanceState? state = null, CustomResourceOptions? options = null)
        {
            return new BdsInstance(name, id, state, options);
        }
    }

    public sealed class BdsInstanceArgs : Pulumi.ResourceArgs
    {
        [Input("cloudSqlDetails")]
        private InputList<Inputs.BdsInstanceCloudSqlDetailArgs>? _cloudSqlDetails;

        /// <summary>
        /// The information about added Cloud SQL capability
        /// </summary>
        public InputList<Inputs.BdsInstanceCloudSqlDetailArgs> CloudSqlDetails
        {
            get => _cloudSqlDetails ?? (_cloudSqlDetails = new InputList<Inputs.BdsInstanceCloudSqlDetailArgs>());
            set => _cloudSqlDetails = value;
        }

        /// <summary>
        /// Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
        /// </summary>
        [Input("clusterAdminPassword", required: true)]
        public Input<string> ClusterAdminPassword { get; set; } = null!;

        /// <summary>
        /// The SSH public key used to authenticate the cluster connection.
        /// </summary>
        [Input("clusterPublicKey", required: true)]
        public Input<string> ClusterPublicKey { get; set; } = null!;

        /// <summary>
        /// Version of the Hadoop distribution.
        /// </summary>
        [Input("clusterVersion", required: true)]
        public Input<string> ClusterVersion { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example, `{"foo-namespace": {"bar-key": "value"}}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Name of the Big Data Service cluster.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. For example, `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Boolean flag specifying whether or not Cloud SQL should be configured.
        /// </summary>
        [Input("isCloudSqlConfigured")]
        public Input<bool>? IsCloudSqlConfigured { get; set; }

        /// <summary>
        /// Boolean flag specifying whether or not the cluster is highly available (HA).
        /// </summary>
        [Input("isHighAvailability", required: true)]
        public Input<bool> IsHighAvailability { get; set; } = null!;

        /// <summary>
        /// Boolean flag specifying whether or not the cluster should be set up as secure.
        /// </summary>
        [Input("isSecure", required: true)]
        public Input<bool> IsSecure { get; set; } = null!;

        [Input("masterNode", required: true)]
        public Input<Inputs.BdsInstanceMasterNodeArgs> MasterNode { get; set; } = null!;

        /// <summary>
        /// Additional configuration of the user's network.
        /// </summary>
        [Input("networkConfig")]
        public Input<Inputs.BdsInstanceNetworkConfigArgs>? NetworkConfig { get; set; }

        [Input("utilNode", required: true)]
        public Input<Inputs.BdsInstanceUtilNodeArgs> UtilNode { get; set; } = null!;

        [Input("workerNode", required: true)]
        public Input<Inputs.BdsInstanceWorkerNodeArgs> WorkerNode { get; set; } = null!;

        public BdsInstanceArgs()
        {
        }
    }

    public sealed class BdsInstanceState : Pulumi.ResourceArgs
    {
        [Input("cloudSqlDetails")]
        private InputList<Inputs.BdsInstanceCloudSqlDetailGetArgs>? _cloudSqlDetails;

        /// <summary>
        /// The information about added Cloud SQL capability
        /// </summary>
        public InputList<Inputs.BdsInstanceCloudSqlDetailGetArgs> CloudSqlDetails
        {
            get => _cloudSqlDetails ?? (_cloudSqlDetails = new InputList<Inputs.BdsInstanceCloudSqlDetailGetArgs>());
            set => _cloudSqlDetails = value;
        }

        /// <summary>
        /// Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
        /// </summary>
        [Input("clusterAdminPassword")]
        public Input<string>? ClusterAdminPassword { get; set; }

        [Input("clusterDetails")]
        private InputList<Inputs.BdsInstanceClusterDetailGetArgs>? _clusterDetails;

        /// <summary>
        /// Specific info about a Hadoop cluster
        /// </summary>
        public InputList<Inputs.BdsInstanceClusterDetailGetArgs> ClusterDetails
        {
            get => _clusterDetails ?? (_clusterDetails = new InputList<Inputs.BdsInstanceClusterDetailGetArgs>());
            set => _clusterDetails = value;
        }

        /// <summary>
        /// The SSH public key used to authenticate the cluster connection.
        /// </summary>
        [Input("clusterPublicKey")]
        public Input<string>? ClusterPublicKey { get; set; }

        /// <summary>
        /// Version of the Hadoop distribution.
        /// </summary>
        [Input("clusterVersion")]
        public Input<string>? ClusterVersion { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The user who created the cluster.
        /// </summary>
        [Input("createdBy")]
        public Input<string>? CreatedBy { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example, `{"foo-namespace": {"bar-key": "value"}}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Name of the Big Data Service cluster.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. For example, `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Boolean flag specifying whether or not Cloud SQL should be configured.
        /// </summary>
        [Input("isCloudSqlConfigured")]
        public Input<bool>? IsCloudSqlConfigured { get; set; }

        /// <summary>
        /// Boolean flag specifying whether or not the cluster is highly available (HA).
        /// </summary>
        [Input("isHighAvailability")]
        public Input<bool>? IsHighAvailability { get; set; }

        /// <summary>
        /// Boolean flag specifying whether or not the cluster should be set up as secure.
        /// </summary>
        [Input("isSecure")]
        public Input<bool>? IsSecure { get; set; }

        [Input("masterNode")]
        public Input<Inputs.BdsInstanceMasterNodeGetArgs>? MasterNode { get; set; }

        /// <summary>
        /// Additional configuration of the user's network.
        /// </summary>
        [Input("networkConfig")]
        public Input<Inputs.BdsInstanceNetworkConfigGetArgs>? NetworkConfig { get; set; }

        [Input("nodes")]
        private InputList<Inputs.BdsInstanceNodeGetArgs>? _nodes;

        /// <summary>
        /// The list of nodes in the Big Data Service cluster.
        /// </summary>
        public InputList<Inputs.BdsInstanceNodeGetArgs> Nodes
        {
            get => _nodes ?? (_nodes = new InputList<Inputs.BdsInstanceNodeGetArgs>());
            set => _nodes = value;
        }

        /// <summary>
        /// The number of nodes that form the cluster.
        /// </summary>
        [Input("numberOfNodes")]
        public Input<int>? NumberOfNodes { get; set; }

        /// <summary>
        /// The state of the cluster.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the cluster was updated, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        [Input("utilNode")]
        public Input<Inputs.BdsInstanceUtilNodeGetArgs>? UtilNode { get; set; }

        [Input("workerNode")]
        public Input<Inputs.BdsInstanceWorkerNodeGetArgs>? WorkerNode { get; set; }

        public BdsInstanceState()
        {
        }
    }
}
