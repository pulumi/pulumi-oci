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
    /// This resource provides the Migration Plan resource in Oracle Cloud Infrastructure Cloud Migrations service.
    /// 
    /// Creates a migration plan.
    /// 
    /// ## Import
    /// 
    /// MigrationPlans can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:CloudMigrations/migrationPlan:MigrationPlan test_migration_plan "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CloudMigrations/migrationPlan:MigrationPlan")]
    public partial class MigrationPlan : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
        /// </summary>
        [Output("calculatedLimits")]
        public Output<ImmutableDictionary<string, object>> CalculatedLimits { get; private set; } = null!;

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
        /// (Updatable) Migration plan identifier
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the associated migration.
        /// </summary>
        [Output("migrationId")]
        public Output<string> MigrationId { get; private set; } = null!;

        /// <summary>
        /// Status of the migration plan.
        /// </summary>
        [Output("migrationPlanStats")]
        public Output<ImmutableArray<Outputs.MigrationPlanMigrationPlanStat>> MigrationPlanStats { get; private set; } = null!;

        /// <summary>
        /// OCID of the referenced ORM job.
        /// </summary>
        [Output("referenceToRmsStack")]
        public Output<string> ReferenceToRmsStack { get; private set; } = null!;

        /// <summary>
        /// Source migraiton plan ID to be cloned.
        /// </summary>
        [Output("sourceMigrationPlanId")]
        public Output<string> SourceMigrationPlanId { get; private set; } = null!;

        /// <summary>
        /// The current state of the migration plan.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of strategies for the resources to be migrated.
        /// </summary>
        [Output("strategies")]
        public Output<ImmutableArray<Outputs.MigrationPlanStrategy>> Strategies { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of target environments.
        /// </summary>
        [Output("targetEnvironments")]
        public Output<ImmutableArray<Outputs.MigrationPlanTargetEnvironment>> TargetEnvironments { get; private set; } = null!;

        /// <summary>
        /// The time when the migration plan was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the migration plan was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a MigrationPlan resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MigrationPlan(string name, MigrationPlanArgs args, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migrationPlan:MigrationPlan", name, args ?? new MigrationPlanArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MigrationPlan(string name, Input<string> id, MigrationPlanState? state = null, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migrationPlan:MigrationPlan", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing MigrationPlan resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MigrationPlan Get(string name, Input<string> id, MigrationPlanState? state = null, CustomResourceOptions? options = null)
        {
            return new MigrationPlan(name, id, state, options);
        }
    }

    public sealed class MigrationPlanArgs : global::Pulumi.ResourceArgs
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
        /// (Updatable) Migration plan identifier
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
        /// The OCID of the associated migration.
        /// </summary>
        [Input("migrationId", required: true)]
        public Input<string> MigrationId { get; set; } = null!;

        /// <summary>
        /// Source migraiton plan ID to be cloned.
        /// </summary>
        [Input("sourceMigrationPlanId")]
        public Input<string>? SourceMigrationPlanId { get; set; }

        [Input("strategies")]
        private InputList<Inputs.MigrationPlanStrategyArgs>? _strategies;

        /// <summary>
        /// (Updatable) List of strategies for the resources to be migrated.
        /// </summary>
        public InputList<Inputs.MigrationPlanStrategyArgs> Strategies
        {
            get => _strategies ?? (_strategies = new InputList<Inputs.MigrationPlanStrategyArgs>());
            set => _strategies = value;
        }

        [Input("targetEnvironments")]
        private InputList<Inputs.MigrationPlanTargetEnvironmentArgs>? _targetEnvironments;

        /// <summary>
        /// (Updatable) List of target environments.
        /// </summary>
        public InputList<Inputs.MigrationPlanTargetEnvironmentArgs> TargetEnvironments
        {
            get => _targetEnvironments ?? (_targetEnvironments = new InputList<Inputs.MigrationPlanTargetEnvironmentArgs>());
            set => _targetEnvironments = value;
        }

        public MigrationPlanArgs()
        {
        }
        public static new MigrationPlanArgs Empty => new MigrationPlanArgs();
    }

    public sealed class MigrationPlanState : global::Pulumi.ResourceArgs
    {
        [Input("calculatedLimits")]
        private InputMap<object>? _calculatedLimits;

        /// <summary>
        /// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
        /// </summary>
        public InputMap<object> CalculatedLimits
        {
            get => _calculatedLimits ?? (_calculatedLimits = new InputMap<object>());
            set => _calculatedLimits = value;
        }

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
        /// (Updatable) Migration plan identifier
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
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the associated migration.
        /// </summary>
        [Input("migrationId")]
        public Input<string>? MigrationId { get; set; }

        [Input("migrationPlanStats")]
        private InputList<Inputs.MigrationPlanMigrationPlanStatGetArgs>? _migrationPlanStats;

        /// <summary>
        /// Status of the migration plan.
        /// </summary>
        public InputList<Inputs.MigrationPlanMigrationPlanStatGetArgs> MigrationPlanStats
        {
            get => _migrationPlanStats ?? (_migrationPlanStats = new InputList<Inputs.MigrationPlanMigrationPlanStatGetArgs>());
            set => _migrationPlanStats = value;
        }

        /// <summary>
        /// OCID of the referenced ORM job.
        /// </summary>
        [Input("referenceToRmsStack")]
        public Input<string>? ReferenceToRmsStack { get; set; }

        /// <summary>
        /// Source migraiton plan ID to be cloned.
        /// </summary>
        [Input("sourceMigrationPlanId")]
        public Input<string>? SourceMigrationPlanId { get; set; }

        /// <summary>
        /// The current state of the migration plan.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("strategies")]
        private InputList<Inputs.MigrationPlanStrategyGetArgs>? _strategies;

        /// <summary>
        /// (Updatable) List of strategies for the resources to be migrated.
        /// </summary>
        public InputList<Inputs.MigrationPlanStrategyGetArgs> Strategies
        {
            get => _strategies ?? (_strategies = new InputList<Inputs.MigrationPlanStrategyGetArgs>());
            set => _strategies = value;
        }

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

        [Input("targetEnvironments")]
        private InputList<Inputs.MigrationPlanTargetEnvironmentGetArgs>? _targetEnvironments;

        /// <summary>
        /// (Updatable) List of target environments.
        /// </summary>
        public InputList<Inputs.MigrationPlanTargetEnvironmentGetArgs> TargetEnvironments
        {
            get => _targetEnvironments ?? (_targetEnvironments = new InputList<Inputs.MigrationPlanTargetEnvironmentGetArgs>());
            set => _targetEnvironments = value;
        }

        /// <summary>
        /// The time when the migration plan was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the migration plan was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public MigrationPlanState()
        {
        }
        public static new MigrationPlanState Empty => new MigrationPlanState();
    }
}