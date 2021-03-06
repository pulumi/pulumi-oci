// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Target Alert Policy Association resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Creates a new target-alert policy association to track a alert policy applied on target.
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
    ///         var testTargetAlertPolicyAssociation = new Oci.DataSafe.TargetAlertPolicyAssociation("testTargetAlertPolicyAssociation", new Oci.DataSafe.TargetAlertPolicyAssociationArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             IsEnabled = @var.Target_alert_policy_association_is_enabled,
    ///             PolicyId = oci_identity_policy.Test_policy.Id,
    ///             TargetId = oci_cloud_guard_target.Test_target.Id,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             Description = @var.Target_alert_policy_association_description,
    ///             DisplayName = @var.Target_alert_policy_association_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// TargetAlertPolicyAssociations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataSafe/targetAlertPolicyAssociation:TargetAlertPolicyAssociation test_target_alert_policy_association "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/targetAlertPolicyAssociation:TargetAlertPolicyAssociation")]
    public partial class TargetAlertPolicyAssociation : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where the target-alert policy association is created.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Describes the target-alert policy association.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the target-alert policy association.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if the target-alert policy association is enabled or disabled.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        [Output("policyId")]
        public Output<string> PolicyId { get; private set; } = null!;

        /// <summary>
        /// The current state of the target-alert policy association.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The OCID of the target.
        /// </summary>
        [Output("targetId")]
        public Output<string> TargetId { get; private set; } = null!;

        /// <summary>
        /// Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a TargetAlertPolicyAssociation resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public TargetAlertPolicyAssociation(string name, TargetAlertPolicyAssociationArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/targetAlertPolicyAssociation:TargetAlertPolicyAssociation", name, args ?? new TargetAlertPolicyAssociationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private TargetAlertPolicyAssociation(string name, Input<string> id, TargetAlertPolicyAssociationState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/targetAlertPolicyAssociation:TargetAlertPolicyAssociation", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing TargetAlertPolicyAssociation resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static TargetAlertPolicyAssociation Get(string name, Input<string> id, TargetAlertPolicyAssociationState? state = null, CustomResourceOptions? options = null)
        {
            return new TargetAlertPolicyAssociation(name, id, state, options);
        }
    }

    public sealed class TargetAlertPolicyAssociationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where the target-alert policy association is created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Describes the target-alert policy association.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the target-alert policy association.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if the target-alert policy association is enabled or disabled.
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        [Input("policyId", required: true)]
        public Input<string> PolicyId { get; set; } = null!;

        /// <summary>
        /// The OCID of the target.
        /// </summary>
        [Input("targetId", required: true)]
        public Input<string> TargetId { get; set; } = null!;

        public TargetAlertPolicyAssociationArgs()
        {
        }
    }

    public sealed class TargetAlertPolicyAssociationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where the target-alert policy association is created.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Describes the target-alert policy association.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the target-alert policy association.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if the target-alert policy association is enabled or disabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        [Input("policyId")]
        public Input<string>? PolicyId { get; set; }

        /// <summary>
        /// The current state of the target-alert policy association.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The OCID of the target.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public TargetAlertPolicyAssociationState()
        {
        }
    }
}
