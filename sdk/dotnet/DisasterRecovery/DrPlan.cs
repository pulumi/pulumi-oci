// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery
{
    /// <summary>
    /// This resource provides the Dr Plan resource in Oracle Cloud Infrastructure Disaster Recovery service.
    /// 
    /// Creates a new DR Plan of the specified DR Plan type.
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
    ///     var testDrPlan = new Oci.DisasterRecovery.DrPlan("testDrPlan", new()
    ///     {
    ///         DisplayName = @var.Dr_plan_display_name,
    ///         DrProtectionGroupId = oci_disaster_recovery_dr_protection_group.Test_dr_protection_group.Id,
    ///         Type = @var.Dr_plan_type,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// DrPlans can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DisasterRecovery/drPlan:DrPlan test_dr_plan "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DisasterRecovery/drPlan:DrPlan")]
    public partial class DrPlan : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The OCID of the DR Protection Group to which this DR Plan belongs.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
        /// </summary>
        [Output("drProtectionGroupId")]
        public Output<string> DrProtectionGroupId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the DR Plan's current state in more detail.
        /// </summary>
        [Output("lifeCycleDetails")]
        public Output<string> LifeCycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
        /// </summary>
        [Output("peerDrProtectionGroupId")]
        public Output<string> PeerDrProtectionGroupId { get; private set; } = null!;

        /// <summary>
        /// The region of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `us-phoenix-1`
        /// </summary>
        [Output("peerRegion")]
        public Output<string> PeerRegion { get; private set; } = null!;

        /// <summary>
        /// The list of groups in this DR Plan.
        /// </summary>
        [Output("planGroups")]
        public Output<ImmutableArray<Outputs.DrPlanPlanGroup>> PlanGroups { get; private set; } = null!;

        /// <summary>
        /// The current state of the DR Plan.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The type of DR Plan to be created.
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;


        /// <summary>
        /// Create a DrPlan resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DrPlan(string name, DrPlanArgs args, CustomResourceOptions? options = null)
            : base("oci:DisasterRecovery/drPlan:DrPlan", name, args ?? new DrPlanArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DrPlan(string name, Input<string> id, DrPlanState? state = null, CustomResourceOptions? options = null)
            : base("oci:DisasterRecovery/drPlan:DrPlan", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DrPlan resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DrPlan Get(string name, Input<string> id, DrPlanState? state = null, CustomResourceOptions? options = null)
        {
            return new DrPlan(name, id, state, options);
        }
    }

    public sealed class DrPlanArgs : global::Pulumi.ResourceArgs
    {
        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// The OCID of the DR Protection Group to which this DR Plan belongs.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
        /// </summary>
        [Input("drProtectionGroupId", required: true)]
        public Input<string> DrProtectionGroupId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The type of DR Plan to be created.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DrPlanArgs()
        {
        }
        public static new DrPlanArgs Empty => new DrPlanArgs();
    }

    public sealed class DrPlanState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The OCID of the DR Protection Group to which this DR Plan belongs.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
        /// </summary>
        [Input("drProtectionGroupId")]
        public Input<string>? DrProtectionGroupId { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the DR Plan's current state in more detail.
        /// </summary>
        [Input("lifeCycleDetails")]
        public Input<string>? LifeCycleDetails { get; set; }

        /// <summary>
        /// The OCID of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
        /// </summary>
        [Input("peerDrProtectionGroupId")]
        public Input<string>? PeerDrProtectionGroupId { get; set; }

        /// <summary>
        /// The region of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `us-phoenix-1`
        /// </summary>
        [Input("peerRegion")]
        public Input<string>? PeerRegion { get; set; }

        [Input("planGroups")]
        private InputList<Inputs.DrPlanPlanGroupGetArgs>? _planGroups;

        /// <summary>
        /// The list of groups in this DR Plan.
        /// </summary>
        public InputList<Inputs.DrPlanPlanGroupGetArgs> PlanGroups
        {
            get => _planGroups ?? (_planGroups = new InputList<Inputs.DrPlanPlanGroupGetArgs>());
            set => _planGroups = value;
        }

        /// <summary>
        /// The current state of the DR Plan.
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
        /// The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The type of DR Plan to be created.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public DrPlanState()
        {
        }
        public static new DrPlanState Empty => new DrPlanState();
    }
}