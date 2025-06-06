// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Database Security Config Management resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Updates the database security configuration.
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
    ///     var testDatabaseSecurityConfigManagement = new Oci.DataSafe.DatabaseSecurityConfigManagement("test_database_security_config_management", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         TargetId = testTargetDatabase.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = databaseSecurityConfigManagementDescription,
    ///         DisplayName = databaseSecurityConfigManagementDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         SqlFirewallConfig = new Oci.DataSafe.Inputs.DatabaseSecurityConfigManagementSqlFirewallConfigArgs
    ///         {
    ///             ExcludeJob = databaseSecurityConfigManagementSqlFirewallConfigExcludeJob,
    ///             Status = databaseSecurityConfigManagementSqlFirewallConfigStatus,
    ///             ViolationLogAutoPurge = databaseSecurityConfigManagementSqlFirewallConfigViolationLogAutoPurge,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:DataSafe/databaseSecurityConfigManagement:DatabaseSecurityConfigManagement")]
    public partial class DatabaseSecurityConfigManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment containing the database security config.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the security policy.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the database security config. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Details about the current state of the database security config in Data Safe.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("refreshTrigger")]
        public Output<bool?> RefreshTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details to update the SQL firewall config.
        /// </summary>
        [Output("sqlFirewallConfig")]
        public Output<Outputs.DatabaseSecurityConfigManagementSqlFirewallConfig> SqlFirewallConfig { get; private set; } = null!;

        /// <summary>
        /// The current state of the database security config.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// Unique target identifier.
        /// </summary>
        [Output("targetId")]
        public Output<string?> TargetId { get; private set; } = null!;

        /// <summary>
        /// The time that the database security config was created, in the format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The last date and time the database security config was refreshed, in the format defined by RFC3339.
        /// </summary>
        [Output("timeLastRefreshed")]
        public Output<string> TimeLastRefreshed { get; private set; } = null!;

        /// <summary>
        /// The date and time the database security configuration was last updated, in the format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a DatabaseSecurityConfigManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DatabaseSecurityConfigManagement(string name, DatabaseSecurityConfigManagementArgs? args = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/databaseSecurityConfigManagement:DatabaseSecurityConfigManagement", name, args ?? new DatabaseSecurityConfigManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DatabaseSecurityConfigManagement(string name, Input<string> id, DatabaseSecurityConfigManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/databaseSecurityConfigManagement:DatabaseSecurityConfigManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DatabaseSecurityConfigManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DatabaseSecurityConfigManagement Get(string name, Input<string> id, DatabaseSecurityConfigManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new DatabaseSecurityConfigManagement(name, id, state, options);
        }
    }

    public sealed class DatabaseSecurityConfigManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment containing the database security config.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the security policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the database security config. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("refreshTrigger")]
        public Input<bool>? RefreshTrigger { get; set; }

        /// <summary>
        /// (Updatable) Details to update the SQL firewall config.
        /// </summary>
        [Input("sqlFirewallConfig")]
        public Input<Inputs.DatabaseSecurityConfigManagementSqlFirewallConfigArgs>? SqlFirewallConfig { get; set; }

        /// <summary>
        /// Unique target identifier.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        public DatabaseSecurityConfigManagementArgs()
        {
        }
        public static new DatabaseSecurityConfigManagementArgs Empty => new DatabaseSecurityConfigManagementArgs();
    }

    public sealed class DatabaseSecurityConfigManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment containing the database security config.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the security policy.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the database security config. The name does not have to be unique, and it is changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Details about the current state of the database security config in Data Safe.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("refreshTrigger")]
        public Input<bool>? RefreshTrigger { get; set; }

        /// <summary>
        /// (Updatable) Details to update the SQL firewall config.
        /// </summary>
        [Input("sqlFirewallConfig")]
        public Input<Inputs.DatabaseSecurityConfigManagementSqlFirewallConfigGetArgs>? SqlFirewallConfig { get; set; }

        /// <summary>
        /// The current state of the database security config.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// Unique target identifier.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// The time that the database security config was created, in the format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The last date and time the database security config was refreshed, in the format defined by RFC3339.
        /// </summary>
        [Input("timeLastRefreshed")]
        public Input<string>? TimeLastRefreshed { get; set; }

        /// <summary>
        /// The date and time the database security configuration was last updated, in the format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DatabaseSecurityConfigManagementState()
        {
        }
        public static new DatabaseSecurityConfigManagementState Empty => new DatabaseSecurityConfigManagementState();
    }
}
