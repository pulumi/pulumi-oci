// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.EmWarehouse
{
    /// <summary>
    /// This resource provides the Em Warehouse resource in Oracle Cloud Infrastructure Em Warehouse service.
    /// 
    /// Creates a new EmWarehouse.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testEmWarehouse = new Oci.EmWarehouse.EmWarehouse("testEmWarehouse", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         EmBridgeId = oci_em_warehouse_em_bridge.Test_em_bridge.Id,
    ///         OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         DisplayName = @var.Em_warehouse_display_name,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// EmWarehouses can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:EmWarehouse/emWarehouse:EmWarehouse test_em_warehouse "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:EmWarehouse/emWarehouse:EmWarehouse")]
    public partial class EmWarehouse : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// EmWarehouse Identifier
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) EMBridge Identifier
        /// </summary>
        [Output("emBridgeId")]
        public Output<string> EmBridgeId { get; private set; } = null!;

        /// <summary>
        /// Type of the EmWarehouse.
        /// </summary>
        [Output("emWarehouseType")]
        public Output<string> EmWarehouseType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Data Flow Run Status Message
        /// </summary>
        [Output("latestEtlRunMessage")]
        public Output<string> LatestEtlRunMessage { get; private set; } = null!;

        /// <summary>
        /// Data Flow Run Status
        /// </summary>
        [Output("latestEtlRunStatus")]
        public Output<string> LatestEtlRunStatus { get; private set; } = null!;

        /// <summary>
        /// Data Flow Run Total Time
        /// </summary>
        [Output("latestEtlRunTime")]
        public Output<string> LatestEtlRunTime { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// operations Insights Warehouse Identifier
        /// </summary>
        [Output("operationsInsightsWarehouseId")]
        public Output<string> OperationsInsightsWarehouseId { get; private set; } = null!;

        /// <summary>
        /// The current state of the EmWarehouse.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the the EmWarehouse was created. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the EmWarehouse was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a EmWarehouse resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public EmWarehouse(string name, EmWarehouseArgs args, CustomResourceOptions? options = null)
            : base("oci:EmWarehouse/emWarehouse:EmWarehouse", name, args ?? new EmWarehouseArgs(), MakeResourceOptions(options, ""))
        {
        }

        private EmWarehouse(string name, Input<string> id, EmWarehouseState? state = null, CustomResourceOptions? options = null)
            : base("oci:EmWarehouse/emWarehouse:EmWarehouse", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing EmWarehouse resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static EmWarehouse Get(string name, Input<string> id, EmWarehouseState? state = null, CustomResourceOptions? options = null)
        {
            return new EmWarehouse(name, id, state, options);
        }
    }

    public sealed class EmWarehouseArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// EmWarehouse Identifier
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) EMBridge Identifier
        /// </summary>
        [Input("emBridgeId", required: true)]
        public Input<string> EmBridgeId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// operations Insights Warehouse Identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId", required: true)]
        public Input<string> OperationsInsightsWarehouseId { get; set; } = null!;

        public EmWarehouseArgs()
        {
        }
        public static new EmWarehouseArgs Empty => new EmWarehouseArgs();
    }

    public sealed class EmWarehouseState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// EmWarehouse Identifier
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) EMBridge Identifier
        /// </summary>
        [Input("emBridgeId")]
        public Input<string>? EmBridgeId { get; set; }

        /// <summary>
        /// Type of the EmWarehouse.
        /// </summary>
        [Input("emWarehouseType")]
        public Input<string>? EmWarehouseType { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Data Flow Run Status Message
        /// </summary>
        [Input("latestEtlRunMessage")]
        public Input<string>? LatestEtlRunMessage { get; set; }

        /// <summary>
        /// Data Flow Run Status
        /// </summary>
        [Input("latestEtlRunStatus")]
        public Input<string>? LatestEtlRunStatus { get; set; }

        /// <summary>
        /// Data Flow Run Total Time
        /// </summary>
        [Input("latestEtlRunTime")]
        public Input<string>? LatestEtlRunTime { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// operations Insights Warehouse Identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId")]
        public Input<string>? OperationsInsightsWarehouseId { get; set; }

        /// <summary>
        /// The current state of the EmWarehouse.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the the EmWarehouse was created. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the EmWarehouse was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public EmWarehouseState()
        {
        }
        public static new EmWarehouseState Empty => new EmWarehouseState();
    }
}