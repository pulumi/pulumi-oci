// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    [OciResourceType("oci:DataSafe/databaseSecurityConfigManagement:DatabaseSecurityConfigManagement")]
    public partial class DatabaseSecurityConfigManagement : global::Pulumi.CustomResource
    {
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        [Output("refreshTrigger")]
        public Output<bool?> RefreshTrigger { get; private set; } = null!;

        [Output("sqlFirewallConfig")]
        public Output<Outputs.DatabaseSecurityConfigManagementSqlFirewallConfig> SqlFirewallConfig { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        [Output("targetId")]
        public Output<string?> TargetId { get; private set; } = null!;

        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        [Output("timeLastRefreshed")]
        public Output<string> TimeLastRefreshed { get; private set; } = null!;

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
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("refreshTrigger")]
        public Input<bool>? RefreshTrigger { get; set; }

        [Input("sqlFirewallConfig")]
        public Input<Inputs.DatabaseSecurityConfigManagementSqlFirewallConfigArgs>? SqlFirewallConfig { get; set; }

        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        public DatabaseSecurityConfigManagementArgs()
        {
        }
        public static new DatabaseSecurityConfigManagementArgs Empty => new DatabaseSecurityConfigManagementArgs();
    }

    public sealed class DatabaseSecurityConfigManagementState : global::Pulumi.ResourceArgs
    {
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("refreshTrigger")]
        public Input<bool>? RefreshTrigger { get; set; }

        [Input("sqlFirewallConfig")]
        public Input<Inputs.DatabaseSecurityConfigManagementSqlFirewallConfigGetArgs>? SqlFirewallConfig { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        [Input("timeLastRefreshed")]
        public Input<string>? TimeLastRefreshed { get; set; }

        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DatabaseSecurityConfigManagementState()
        {
        }
        public static new DatabaseSecurityConfigManagementState Empty => new DatabaseSecurityConfigManagementState();
    }
}