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
    /// This resource provides the Audit Policy resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Updates the audit policy.
    /// 
    /// ## Import
    /// 
    /// AuditPolicies can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataSafe/auditPolicy:AuditPolicy test_audit_policy "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/auditPolicy:AuditPolicy")]
    public partial class AuditPolicy : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Lists the audit policy provisioning conditions for the target database.
        /// </summary>
        [Output("auditConditions")]
        public Output<ImmutableArray<Outputs.AuditPolicyAuditCondition>> AuditConditions { get; private set; } = null!;

        /// <summary>
        /// Unique audit policy identifier.
        /// </summary>
        [Output("auditPolicyId")]
        public Output<string> AuditPolicyId { get; private set; } = null!;

        /// <summary>
        /// Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
        /// </summary>
        [Output("auditSpecifications")]
        public Output<ImmutableArray<Outputs.AuditPolicyAuditSpecification>> AuditSpecifications { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the audit policy.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the audit policy.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
        /// </summary>
        [Output("isDataSafeServiceAccountExcluded")]
        public Output<bool> IsDataSafeServiceAccountExcluded { get; private set; } = null!;

        /// <summary>
        /// Details about the current state of the audit policy in Data Safe.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Provision. Could be set to any integer value.
        /// </summary>
        [Output("provisionTrigger")]
        public Output<int?> ProvisionTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Retrieve From Target. Could be set to any integer value.
        /// </summary>
        [Output("retrieveFromTargetTrigger")]
        public Output<int?> RetrieveFromTargetTrigger { get; private set; } = null!;

        /// <summary>
        /// The current state of the audit policy.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The OCID of the target for which the audit policy is created.
        /// </summary>
        [Output("targetId")]
        public Output<string> TargetId { get; private set; } = null!;

        /// <summary>
        /// The time the the audit policy was created, in the format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
        /// </summary>
        [Output("timeLastProvisioned")]
        public Output<string> TimeLastProvisioned { get; private set; } = null!;

        /// <summary>
        /// The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
        /// </summary>
        [Output("timeLastRetrieved")]
        public Output<string> TimeLastRetrieved { get; private set; } = null!;

        /// <summary>
        /// The last date and time the audit policy was updated, in the format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a AuditPolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AuditPolicy(string name, AuditPolicyArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/auditPolicy:AuditPolicy", name, args ?? new AuditPolicyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AuditPolicy(string name, Input<string> id, AuditPolicyState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/auditPolicy:AuditPolicy", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing AuditPolicy resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AuditPolicy Get(string name, Input<string> id, AuditPolicyState? state = null, CustomResourceOptions? options = null)
        {
            return new AuditPolicy(name, id, state, options);
        }
    }

    public sealed class AuditPolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique audit policy identifier.
        /// </summary>
        [Input("auditPolicyId", required: true)]
        public Input<string> AuditPolicyId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the audit policy.
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
        /// (Updatable) The description of the audit policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
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
        /// (Updatable) An optional property when incremented triggers Provision. Could be set to any integer value.
        /// </summary>
        [Input("provisionTrigger")]
        public Input<int>? ProvisionTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Retrieve From Target. Could be set to any integer value.
        /// </summary>
        [Input("retrieveFromTargetTrigger")]
        public Input<int>? RetrieveFromTargetTrigger { get; set; }

        public AuditPolicyArgs()
        {
        }
        public static new AuditPolicyArgs Empty => new AuditPolicyArgs();
    }

    public sealed class AuditPolicyState : global::Pulumi.ResourceArgs
    {
        [Input("auditConditions")]
        private InputList<Inputs.AuditPolicyAuditConditionGetArgs>? _auditConditions;

        /// <summary>
        /// Lists the audit policy provisioning conditions for the target database.
        /// </summary>
        public InputList<Inputs.AuditPolicyAuditConditionGetArgs> AuditConditions
        {
            get => _auditConditions ?? (_auditConditions = new InputList<Inputs.AuditPolicyAuditConditionGetArgs>());
            set => _auditConditions = value;
        }

        /// <summary>
        /// Unique audit policy identifier.
        /// </summary>
        [Input("auditPolicyId")]
        public Input<string>? AuditPolicyId { get; set; }

        [Input("auditSpecifications")]
        private InputList<Inputs.AuditPolicyAuditSpecificationGetArgs>? _auditSpecifications;

        /// <summary>
        /// Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
        /// </summary>
        public InputList<Inputs.AuditPolicyAuditSpecificationGetArgs> AuditSpecifications
        {
            get => _auditSpecifications ?? (_auditSpecifications = new InputList<Inputs.AuditPolicyAuditSpecificationGetArgs>());
            set => _auditSpecifications = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the audit policy.
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
        /// (Updatable) The description of the audit policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
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
        /// Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
        /// </summary>
        [Input("isDataSafeServiceAccountExcluded")]
        public Input<bool>? IsDataSafeServiceAccountExcluded { get; set; }

        /// <summary>
        /// Details about the current state of the audit policy in Data Safe.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Provision. Could be set to any integer value.
        /// </summary>
        [Input("provisionTrigger")]
        public Input<int>? ProvisionTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Retrieve From Target. Could be set to any integer value.
        /// </summary>
        [Input("retrieveFromTargetTrigger")]
        public Input<int>? RetrieveFromTargetTrigger { get; set; }

        /// <summary>
        /// The current state of the audit policy.
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
        /// The OCID of the target for which the audit policy is created.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// The time the the audit policy was created, in the format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
        /// </summary>
        [Input("timeLastProvisioned")]
        public Input<string>? TimeLastProvisioned { get; set; }

        /// <summary>
        /// The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
        /// </summary>
        [Input("timeLastRetrieved")]
        public Input<string>? TimeLastRetrieved { get; set; }

        /// <summary>
        /// The last date and time the audit policy was updated, in the format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public AuditPolicyState()
        {
        }
        public static new AuditPolicyState Empty => new AuditPolicyState();
    }
}