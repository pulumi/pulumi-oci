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
    /// This resource provides the Sql Firewall Policy resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Updates the SQL firewall policy.
    /// 
    /// ## Import
    /// 
    /// SqlFirewallPolicies can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataSafe/sqlFirewallPolicy:SqlFirewallPolicy test_sql_firewall_policy "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/sqlFirewallPolicy:SqlFirewallPolicy")]
    public partial class SqlFirewallPolicy : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) List of allowed ip addresses for the SQL firewall policy.
        /// </summary>
        [Output("allowedClientIps")]
        public Output<ImmutableArray<string>> AllowedClientIps { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of allowed operating system user names for the SQL firewall policy.
        /// </summary>
        [Output("allowedClientOsUsernames")]
        public Output<ImmutableArray<string>> AllowedClientOsUsernames { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of allowed client programs for the SQL firewall policy.
        /// </summary>
        [Output("allowedClientPrograms")]
        public Output<ImmutableArray<string>> AllowedClientPrograms { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the SQL firewall policy.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The database user name.
        /// </summary>
        [Output("dbUserName")]
        public Output<string> DbUserName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the SQL firewall policy.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the SQL firewall policy. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies the SQL firewall policy enforcement option.
        /// </summary>
        [Output("enforcementScope")]
        public Output<string> EnforcementScope { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Details about the current state of the SQL firewall policy in Data Safe.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the security policy corresponding to the SQL firewall policy.
        /// </summary>
        [Output("securityPolicyId")]
        public Output<string> SecurityPolicyId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the SQL firewall policy resource.
        /// </summary>
        [Output("sqlFirewallPolicyId")]
        public Output<string> SqlFirewallPolicyId { get; private set; } = null!;

        /// <summary>
        /// Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
        /// </summary>
        [Output("sqlLevel")]
        public Output<string> SqlLevel { get; private set; } = null!;

        /// <summary>
        /// The current state of the SQL firewall policy.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies whether the SQL firewall policy is enabled or disabled.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time that the SQL firewall policy was created, in the format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the SQL firewall policy was last updated, in the format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies the SQL firewall action based on detection of SQL firewall violations.
        /// </summary>
        [Output("violationAction")]
        public Output<string> ViolationAction { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("violationAudit")]
        public Output<string> ViolationAudit { get; private set; } = null!;


        /// <summary>
        /// Create a SqlFirewallPolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SqlFirewallPolicy(string name, SqlFirewallPolicyArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sqlFirewallPolicy:SqlFirewallPolicy", name, args ?? new SqlFirewallPolicyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SqlFirewallPolicy(string name, Input<string> id, SqlFirewallPolicyState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sqlFirewallPolicy:SqlFirewallPolicy", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SqlFirewallPolicy resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SqlFirewallPolicy Get(string name, Input<string> id, SqlFirewallPolicyState? state = null, CustomResourceOptions? options = null)
        {
            return new SqlFirewallPolicy(name, id, state, options);
        }
    }

    public sealed class SqlFirewallPolicyArgs : global::Pulumi.ResourceArgs
    {
        [Input("allowedClientIps")]
        private InputList<string>? _allowedClientIps;

        /// <summary>
        /// (Updatable) List of allowed ip addresses for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientIps
        {
            get => _allowedClientIps ?? (_allowedClientIps = new InputList<string>());
            set => _allowedClientIps = value;
        }

        [Input("allowedClientOsUsernames")]
        private InputList<string>? _allowedClientOsUsernames;

        /// <summary>
        /// (Updatable) List of allowed operating system user names for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientOsUsernames
        {
            get => _allowedClientOsUsernames ?? (_allowedClientOsUsernames = new InputList<string>());
            set => _allowedClientOsUsernames = value;
        }

        [Input("allowedClientPrograms")]
        private InputList<string>? _allowedClientPrograms;

        /// <summary>
        /// (Updatable) List of allowed client programs for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientPrograms
        {
            get => _allowedClientPrograms ?? (_allowedClientPrograms = new InputList<string>());
            set => _allowedClientPrograms = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the SQL firewall policy.
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
        /// (Updatable) The description of the SQL firewall policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the SQL firewall policy. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) Specifies the SQL firewall policy enforcement option.
        /// </summary>
        [Input("enforcementScope")]
        public Input<string>? EnforcementScope { get; set; }

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
        /// The OCID of the SQL firewall policy resource.
        /// </summary>
        [Input("sqlFirewallPolicyId", required: true)]
        public Input<string> SqlFirewallPolicyId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Specifies whether the SQL firewall policy is enabled or disabled.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// (Updatable) Specifies the SQL firewall action based on detection of SQL firewall violations.
        /// </summary>
        [Input("violationAction")]
        public Input<string>? ViolationAction { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("violationAudit")]
        public Input<string>? ViolationAudit { get; set; }

        public SqlFirewallPolicyArgs()
        {
        }
        public static new SqlFirewallPolicyArgs Empty => new SqlFirewallPolicyArgs();
    }

    public sealed class SqlFirewallPolicyState : global::Pulumi.ResourceArgs
    {
        [Input("allowedClientIps")]
        private InputList<string>? _allowedClientIps;

        /// <summary>
        /// (Updatable) List of allowed ip addresses for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientIps
        {
            get => _allowedClientIps ?? (_allowedClientIps = new InputList<string>());
            set => _allowedClientIps = value;
        }

        [Input("allowedClientOsUsernames")]
        private InputList<string>? _allowedClientOsUsernames;

        /// <summary>
        /// (Updatable) List of allowed operating system user names for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientOsUsernames
        {
            get => _allowedClientOsUsernames ?? (_allowedClientOsUsernames = new InputList<string>());
            set => _allowedClientOsUsernames = value;
        }

        [Input("allowedClientPrograms")]
        private InputList<string>? _allowedClientPrograms;

        /// <summary>
        /// (Updatable) List of allowed client programs for the SQL firewall policy.
        /// </summary>
        public InputList<string> AllowedClientPrograms
        {
            get => _allowedClientPrograms ?? (_allowedClientPrograms = new InputList<string>());
            set => _allowedClientPrograms = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the compartment containing the SQL firewall policy.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The database user name.
        /// </summary>
        [Input("dbUserName")]
        public Input<string>? DbUserName { get; set; }

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
        /// (Updatable) The description of the SQL firewall policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the SQL firewall policy. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) Specifies the SQL firewall policy enforcement option.
        /// </summary>
        [Input("enforcementScope")]
        public Input<string>? EnforcementScope { get; set; }

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
        /// Details about the current state of the SQL firewall policy in Data Safe.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the security policy corresponding to the SQL firewall policy.
        /// </summary>
        [Input("securityPolicyId")]
        public Input<string>? SecurityPolicyId { get; set; }

        /// <summary>
        /// The OCID of the SQL firewall policy resource.
        /// </summary>
        [Input("sqlFirewallPolicyId")]
        public Input<string>? SqlFirewallPolicyId { get; set; }

        /// <summary>
        /// Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
        /// </summary>
        [Input("sqlLevel")]
        public Input<string>? SqlLevel { get; set; }

        /// <summary>
        /// The current state of the SQL firewall policy.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether the SQL firewall policy is enabled or disabled.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

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
        /// The time that the SQL firewall policy was created, in the format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the SQL firewall policy was last updated, in the format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) Specifies the SQL firewall action based on detection of SQL firewall violations.
        /// </summary>
        [Input("violationAction")]
        public Input<string>? ViolationAction { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("violationAudit")]
        public Input<string>? ViolationAudit { get; set; }

        public SqlFirewallPolicyState()
        {
        }
        public static new SqlFirewallPolicyState Empty => new SqlFirewallPolicyState();
    }
}