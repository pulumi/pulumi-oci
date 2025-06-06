// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Compute Gpu Memory Fabric resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Customer can update displayName and tags for compute GPU memory fabric record
    /// 
    /// ## Import
    /// 
    /// ComputeGpuMemoryFabrics can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Core/computeGpuMemoryFabric:ComputeGpuMemoryFabric test_compute_gpu_memory_fabric "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Core/computeGpuMemoryFabric:ComputeGpuMemoryFabric")]
    public partial class ComputeGpuMemoryFabric : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Additional data that can be exposed to the customer. Right now it will include the switch tray ids.
        /// </summary>
        [Output("additionalData")]
        public Output<ImmutableDictionary<string, string>> AdditionalData { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the compute GPU memory fabric.
        /// </summary>
        [Output("computeGpuMemoryFabricId")]
        public Output<string> ComputeGpuMemoryFabricId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique HPC Island
        /// </summary>
        [Output("computeHpcIslandId")]
        public Output<string> ComputeHpcIslandId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Local Block
        /// </summary>
        [Output("computeLocalBlockId")]
        public Output<string> ComputeLocalBlockId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Network Block
        /// </summary>
        [Output("computeNetworkBlockId")]
        public Output<string> ComputeNetworkBlockId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The health state of the GPU memory fabric
        /// </summary>
        [Output("fabricHealth")]
        public Output<string> FabricHealth { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The total number of healthy bare metal hosts located in this compute GPU memory fabric.
        /// </summary>
        [Output("healthyHostCount")]
        public Output<string> HealthyHostCount { get; private set; } = null!;

        /// <summary>
        /// The lifecycle state of the GPU memory fabric
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time that the compute GPU memory fabric record was created, in the format defined by [RFC3339] (https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The total number of bare metal hosts located in this compute GPU memory fabric.
        /// </summary>
        [Output("totalHostCount")]
        public Output<string> TotalHostCount { get; private set; } = null!;


        /// <summary>
        /// Create a ComputeGpuMemoryFabric resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ComputeGpuMemoryFabric(string name, ComputeGpuMemoryFabricArgs args, CustomResourceOptions? options = null)
            : base("oci:Core/computeGpuMemoryFabric:ComputeGpuMemoryFabric", name, args ?? new ComputeGpuMemoryFabricArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ComputeGpuMemoryFabric(string name, Input<string> id, ComputeGpuMemoryFabricState? state = null, CustomResourceOptions? options = null)
            : base("oci:Core/computeGpuMemoryFabric:ComputeGpuMemoryFabric", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ComputeGpuMemoryFabric resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ComputeGpuMemoryFabric Get(string name, Input<string> id, ComputeGpuMemoryFabricState? state = null, CustomResourceOptions? options = null)
        {
            return new ComputeGpuMemoryFabric(name, id, state, options);
        }
    }

    public sealed class ComputeGpuMemoryFabricArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the compute GPU memory fabric.
        /// </summary>
        [Input("computeGpuMemoryFabricId", required: true)]
        public Input<string> ComputeGpuMemoryFabricId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        public ComputeGpuMemoryFabricArgs()
        {
        }
        public static new ComputeGpuMemoryFabricArgs Empty => new ComputeGpuMemoryFabricArgs();
    }

    public sealed class ComputeGpuMemoryFabricState : global::Pulumi.ResourceArgs
    {
        [Input("additionalData")]
        private InputMap<string>? _additionalData;

        /// <summary>
        /// Additional data that can be exposed to the customer. Right now it will include the switch tray ids.
        /// </summary>
        public InputMap<string> AdditionalData
        {
            get => _additionalData ?? (_additionalData = new InputMap<string>());
            set => _additionalData = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the compute GPU memory fabric.
        /// </summary>
        [Input("computeGpuMemoryFabricId")]
        public Input<string>? ComputeGpuMemoryFabricId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique HPC Island
        /// </summary>
        [Input("computeHpcIslandId")]
        public Input<string>? ComputeHpcIslandId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Local Block
        /// </summary>
        [Input("computeLocalBlockId")]
        public Input<string>? ComputeLocalBlockId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Network Block
        /// </summary>
        [Input("computeNetworkBlockId")]
        public Input<string>? ComputeNetworkBlockId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The health state of the GPU memory fabric
        /// </summary>
        [Input("fabricHealth")]
        public Input<string>? FabricHealth { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The total number of healthy bare metal hosts located in this compute GPU memory fabric.
        /// </summary>
        [Input("healthyHostCount")]
        public Input<string>? HealthyHostCount { get; set; }

        /// <summary>
        /// The lifecycle state of the GPU memory fabric
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time that the compute GPU memory fabric record was created, in the format defined by [RFC3339] (https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The total number of bare metal hosts located in this compute GPU memory fabric.
        /// </summary>
        [Input("totalHostCount")]
        public Input<string>? TotalHostCount { get; set; }

        public ComputeGpuMemoryFabricState()
        {
        }
        public static new ComputeGpuMemoryFabricState Empty => new ComputeGpuMemoryFabricState();
    }
}
