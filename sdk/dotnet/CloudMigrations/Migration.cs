// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations
{
    /// <summary>
    /// This resource provides the Migration resource in Oracle Cloud Infrastructure Cloud Migrations service.
    /// 
    /// Creates a migration.
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
    ///     var testMigration = new Oci.CloudMigrations.Migration("testMigration", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         DisplayName = @var.Migration_display_name,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IsCompleted = @var.Migration_is_completed,
    ///         ReplicationScheduleId = oci_cloud_migrations_replication_schedule.Test_replication_schedule.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Migrations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:CloudMigrations/migration:Migration test_migration "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CloudMigrations/migration:Migration")]
    public partial class Migration : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Compartment identifier
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Migration identifier
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates whether migration is marked as complete.
        /// </summary>
        [Output("isCompleted")]
        public Output<bool> IsCompleted { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Output("replicationScheduleId")]
        public Output<string> ReplicationScheduleId { get; private set; } = null!;

        /// <summary>
        /// The current state of migration.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when the migration project was created. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the migration project was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a Migration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Migration(string name, MigrationArgs args, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migration:Migration", name, args ?? new MigrationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Migration(string name, Input<string> id, MigrationState? state = null, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migration:Migration", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Migration resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Migration Get(string name, Input<string> id, MigrationState? state = null, CustomResourceOptions? options = null)
        {
            return new Migration(name, id, state, options);
        }
    }

    public sealed class MigrationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment identifier
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
        /// (Updatable) Migration identifier
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates whether migration is marked as complete.
        /// </summary>
        [Input("isCompleted")]
        public Input<bool>? IsCompleted { get; set; }

        /// <summary>
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Input("replicationScheduleId")]
        public Input<string>? ReplicationScheduleId { get; set; }

        public MigrationArgs()
        {
        }
        public static new MigrationArgs Empty => new MigrationArgs();
    }

    public sealed class MigrationState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment identifier
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
        /// (Updatable) Migration identifier
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates whether migration is marked as complete.
        /// </summary>
        [Input("isCompleted")]
        public Input<bool>? IsCompleted { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Input("replicationScheduleId")]
        public Input<string>? ReplicationScheduleId { get; set; }

        /// <summary>
        /// The current state of migration.
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
        /// The time when the migration project was created. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the migration project was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public MigrationState()
        {
        }
        public static new MigrationState Empty => new MigrationState();
    }
}