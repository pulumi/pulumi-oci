// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetSoftwareUpdate
{
    /// <summary>
    /// This resource provides the Fsu Cycle resource in Oracle Cloud Infrastructure Fleet Software Update service.
    /// 
    /// Creates a new Exadata Fleet Update Cycle.
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
    ///     var testFsuCycle = new Oci.FleetSoftwareUpdate.FsuCycle("test_fsu_cycle", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         FsuCollectionId = testFsuCollection.Id,
    ///         GoalVersionDetails = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleGoalVersionDetailsArgs
    ///         {
    ///             Type = fsuCycleGoalVersionDetailsType,
    ///             HomePolicy = fsuCycleGoalVersionDetailsHomePolicy,
    ///             NewHomePrefix = fsuCycleGoalVersionDetailsNewHomePrefix,
    ///             SoftwareImageId = testImage.Id,
    ///             Version = fsuCycleGoalVersionDetailsVersion,
    ///         },
    ///         Type = fsuCycleType,
    ///         ApplyActionSchedule = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleApplyActionScheduleArgs
    ///         {
    ///             TimeToStart = fsuCycleApplyActionScheduleTimeToStart,
    ///             Type = fsuCycleApplyActionScheduleType,
    ///         },
    ///         BatchingStrategy = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleBatchingStrategyArgs
    ///         {
    ///             IsForceRolling = fsuCycleBatchingStrategyIsForceRolling,
    ///             IsWaitForBatchResume = fsuCycleBatchingStrategyIsWaitForBatchResume,
    ///             Percentage = fsuCycleBatchingStrategyPercentage,
    ///             Type = fsuCycleBatchingStrategyType,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         DiagnosticsCollection = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleDiagnosticsCollectionArgs
    ///         {
    ///             LogCollectionMode = fsuCycleDiagnosticsCollectionLogCollectionMode,
    ///         },
    ///         DisplayName = fsuCycleDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IsIgnoreMissingPatches = fsuCycleIsIgnoreMissingPatches,
    ///         IsIgnorePatches = fsuCycleIsIgnorePatches,
    ///         IsKeepPlacement = fsuCycleIsKeepPlacement,
    ///         MaxDrainTimeoutInSeconds = fsuCycleMaxDrainTimeoutInSeconds,
    ///         StageActionSchedule = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleStageActionScheduleArgs
    ///         {
    ///             TimeToStart = fsuCycleStageActionScheduleTimeToStart,
    ///             Type = fsuCycleStageActionScheduleType,
    ///         },
    ///         UpgradeDetails = new Oci.FleetSoftwareUpdate.Inputs.FsuCycleUpgradeDetailsArgs
    ///         {
    ///             CollectionType = fsuCycleUpgradeDetailsCollectionType,
    ///             IsRecompileInvalidObjects = fsuCycleUpgradeDetailsIsRecompileInvalidObjects,
    ///             IsTimeZoneUpgrade = fsuCycleUpgradeDetailsIsTimeZoneUpgrade,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// FsuCycles can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:FleetSoftwareUpdate/fsuCycle:FsuCycle test_fsu_cycle "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:FleetSoftwareUpdate/fsuCycle:FsuCycle")]
    public partial class FsuCycle : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Output("applyActionSchedule")]
        public Output<Outputs.FsuCycleApplyActionSchedule> ApplyActionSchedule { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
        /// </summary>
        [Output("batchingStrategy")]
        public Output<Outputs.FsuCycleBatchingStrategy> BatchingStrategy { get; private set; } = null!;

        /// <summary>
        /// Type of Exadata Fleet Update collection being upgraded.
        /// </summary>
        [Output("collectionType")]
        public Output<string> CollectionType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
        /// </summary>
        [Output("diagnosticsCollection")]
        public Output<Outputs.FsuCycleDiagnosticsCollection> DiagnosticsCollection { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Exadata Fleet Update Cycle display name.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// OCID identifier for the Action that is currently in execution, if applicable.
        /// </summary>
        [Output("executingFsuActionId")]
        public Output<string> ExecutingFsuActionId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
        /// </summary>
        [Output("fsuCollectionId")]
        public Output<string> FsuCollectionId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
        /// </summary>
        [Output("goalVersionDetails")]
        public Output<Outputs.FsuCycleGoalVersionDetails> GoalVersionDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of patch IDs to ignore.
        /// </summary>
        [Output("isIgnoreMissingPatches")]
        public Output<ImmutableArray<string>> IsIgnoreMissingPatches { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Ignore all patches between the source and target homes during patching.
        /// </summary>
        [Output("isIgnorePatches")]
        public Output<bool> IsIgnorePatches { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
        /// </summary>
        [Output("isKeepPlacement")]
        public Output<bool> IsKeepPlacement { get; private set; } = null!;

        /// <summary>
        /// The latest Action type that was completed in the Exadata Fleet Update Cycle. No value would indicate that the Cycle has not completed any Action yet.
        /// </summary>
        [Output("lastCompletedAction")]
        public Output<string> LastCompletedAction { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the latest Action  in the Exadata Fleet Update Cycle.
        /// </summary>
        [Output("lastCompletedActionId")]
        public Output<string> LastCompletedActionId { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Service drain timeout specified in seconds.
        /// </summary>
        [Output("maxDrainTimeoutInSeconds")]
        public Output<int> MaxDrainTimeoutInSeconds { get; private set; } = null!;

        /// <summary>
        /// In this array all the possible actions will be listed. The first element is the suggested Action.
        /// </summary>
        [Output("nextActionToExecutes")]
        public Output<ImmutableArray<Outputs.FsuCycleNextActionToExecute>> NextActionToExecutes { get; private set; } = null!;

        /// <summary>
        /// Current rollback cycle state if rollback maintenance cycle action has been attempted. No value would indicate that the Cycle has not run a rollback maintenance cycle action before.
        /// </summary>
        [Output("rollbackCycleState")]
        public Output<string> RollbackCycleState { get; private set; } = null!;

        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Output("stageActionSchedule")]
        public Output<Outputs.FsuCycleStageActionSchedule> StageActionSchedule { get; private set; } = null!;

        /// <summary>
        /// The current state of the Exadata Fleet Update Cycle.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the Exadata Fleet Update Cycle was created, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the Exadata Fleet Update Cycle was finished, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        [Output("timeFinished")]
        public Output<string> TimeFinished { get; private set; } = null!;

        /// <summary>
        /// The date and time the Exadata Fleet Update Cycle was updated, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Type of Exadata Fleet Update Cycle.
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details of supported upgrade options for DB or GI collection.
        /// </summary>
        [Output("upgradeDetails")]
        public Output<Outputs.FsuCycleUpgradeDetails> UpgradeDetails { get; private set; } = null!;


        /// <summary>
        /// Create a FsuCycle resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public FsuCycle(string name, FsuCycleArgs args, CustomResourceOptions? options = null)
            : base("oci:FleetSoftwareUpdate/fsuCycle:FsuCycle", name, args ?? new FsuCycleArgs(), MakeResourceOptions(options, ""))
        {
        }

        private FsuCycle(string name, Input<string> id, FsuCycleState? state = null, CustomResourceOptions? options = null)
            : base("oci:FleetSoftwareUpdate/fsuCycle:FsuCycle", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing FsuCycle resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static FsuCycle Get(string name, Input<string> id, FsuCycleState? state = null, CustomResourceOptions? options = null)
        {
            return new FsuCycle(name, id, state, options);
        }
    }

    public sealed class FsuCycleArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Input("applyActionSchedule")]
        public Input<Inputs.FsuCycleApplyActionScheduleArgs>? ApplyActionSchedule { get; set; }

        /// <summary>
        /// (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
        /// </summary>
        [Input("batchingStrategy")]
        public Input<Inputs.FsuCycleBatchingStrategyArgs>? BatchingStrategy { get; set; }

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
        /// </summary>
        [Input("diagnosticsCollection")]
        public Input<Inputs.FsuCycleDiagnosticsCollectionArgs>? DiagnosticsCollection { get; set; }

        /// <summary>
        /// (Updatable) Exadata Fleet Update Cycle display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
        /// </summary>
        [Input("fsuCollectionId", required: true)]
        public Input<string> FsuCollectionId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
        /// </summary>
        [Input("goalVersionDetails", required: true)]
        public Input<Inputs.FsuCycleGoalVersionDetailsArgs> GoalVersionDetails { get; set; } = null!;

        [Input("isIgnoreMissingPatches")]
        private InputList<string>? _isIgnoreMissingPatches;

        /// <summary>
        /// (Updatable) List of patch IDs to ignore.
        /// </summary>
        public InputList<string> IsIgnoreMissingPatches
        {
            get => _isIgnoreMissingPatches ?? (_isIgnoreMissingPatches = new InputList<string>());
            set => _isIgnoreMissingPatches = value;
        }

        /// <summary>
        /// (Updatable) Ignore all patches between the source and target homes during patching.
        /// </summary>
        [Input("isIgnorePatches")]
        public Input<bool>? IsIgnorePatches { get; set; }

        /// <summary>
        /// (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
        /// </summary>
        [Input("isKeepPlacement")]
        public Input<bool>? IsKeepPlacement { get; set; }

        /// <summary>
        /// (Updatable) Service drain timeout specified in seconds.
        /// </summary>
        [Input("maxDrainTimeoutInSeconds")]
        public Input<int>? MaxDrainTimeoutInSeconds { get; set; }

        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Input("stageActionSchedule")]
        public Input<Inputs.FsuCycleStageActionScheduleArgs>? StageActionSchedule { get; set; }

        /// <summary>
        /// (Updatable) Type of Exadata Fleet Update Cycle.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) Details of supported upgrade options for DB or GI collection.
        /// </summary>
        [Input("upgradeDetails")]
        public Input<Inputs.FsuCycleUpgradeDetailsArgs>? UpgradeDetails { get; set; }

        public FsuCycleArgs()
        {
        }
        public static new FsuCycleArgs Empty => new FsuCycleArgs();
    }

    public sealed class FsuCycleState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Input("applyActionSchedule")]
        public Input<Inputs.FsuCycleApplyActionScheduleGetArgs>? ApplyActionSchedule { get; set; }

        /// <summary>
        /// (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
        /// </summary>
        [Input("batchingStrategy")]
        public Input<Inputs.FsuCycleBatchingStrategyGetArgs>? BatchingStrategy { get; set; }

        /// <summary>
        /// Type of Exadata Fleet Update collection being upgraded.
        /// </summary>
        [Input("collectionType")]
        public Input<string>? CollectionType { get; set; }

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
        /// </summary>
        [Input("diagnosticsCollection")]
        public Input<Inputs.FsuCycleDiagnosticsCollectionGetArgs>? DiagnosticsCollection { get; set; }

        /// <summary>
        /// (Updatable) Exadata Fleet Update Cycle display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// OCID identifier for the Action that is currently in execution, if applicable.
        /// </summary>
        [Input("executingFsuActionId")]
        public Input<string>? ExecutingFsuActionId { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
        /// </summary>
        [Input("fsuCollectionId")]
        public Input<string>? FsuCollectionId { get; set; }

        /// <summary>
        /// (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
        /// </summary>
        [Input("goalVersionDetails")]
        public Input<Inputs.FsuCycleGoalVersionDetailsGetArgs>? GoalVersionDetails { get; set; }

        [Input("isIgnoreMissingPatches")]
        private InputList<string>? _isIgnoreMissingPatches;

        /// <summary>
        /// (Updatable) List of patch IDs to ignore.
        /// </summary>
        public InputList<string> IsIgnoreMissingPatches
        {
            get => _isIgnoreMissingPatches ?? (_isIgnoreMissingPatches = new InputList<string>());
            set => _isIgnoreMissingPatches = value;
        }

        /// <summary>
        /// (Updatable) Ignore all patches between the source and target homes during patching.
        /// </summary>
        [Input("isIgnorePatches")]
        public Input<bool>? IsIgnorePatches { get; set; }

        /// <summary>
        /// (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
        /// </summary>
        [Input("isKeepPlacement")]
        public Input<bool>? IsKeepPlacement { get; set; }

        /// <summary>
        /// The latest Action type that was completed in the Exadata Fleet Update Cycle. No value would indicate that the Cycle has not completed any Action yet.
        /// </summary>
        [Input("lastCompletedAction")]
        public Input<string>? LastCompletedAction { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the latest Action  in the Exadata Fleet Update Cycle.
        /// </summary>
        [Input("lastCompletedActionId")]
        public Input<string>? LastCompletedActionId { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Service drain timeout specified in seconds.
        /// </summary>
        [Input("maxDrainTimeoutInSeconds")]
        public Input<int>? MaxDrainTimeoutInSeconds { get; set; }

        [Input("nextActionToExecutes")]
        private InputList<Inputs.FsuCycleNextActionToExecuteGetArgs>? _nextActionToExecutes;

        /// <summary>
        /// In this array all the possible actions will be listed. The first element is the suggested Action.
        /// </summary>
        public InputList<Inputs.FsuCycleNextActionToExecuteGetArgs> NextActionToExecutes
        {
            get => _nextActionToExecutes ?? (_nextActionToExecutes = new InputList<Inputs.FsuCycleNextActionToExecuteGetArgs>());
            set => _nextActionToExecutes = value;
        }

        /// <summary>
        /// Current rollback cycle state if rollback maintenance cycle action has been attempted. No value would indicate that the Cycle has not run a rollback maintenance cycle action before.
        /// </summary>
        [Input("rollbackCycleState")]
        public Input<string>? RollbackCycleState { get; set; }

        /// <summary>
        /// Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
        /// </summary>
        [Input("stageActionSchedule")]
        public Input<Inputs.FsuCycleStageActionScheduleGetArgs>? StageActionSchedule { get; set; }

        /// <summary>
        /// The current state of the Exadata Fleet Update Cycle.
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
        /// The date and time the Exadata Fleet Update Cycle was created, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the Exadata Fleet Update Cycle was finished, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        [Input("timeFinished")]
        public Input<string>? TimeFinished { get; set; }

        /// <summary>
        /// The date and time the Exadata Fleet Update Cycle was updated, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) Type of Exadata Fleet Update Cycle.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// (Updatable) Details of supported upgrade options for DB or GI collection.
        /// </summary>
        [Input("upgradeDetails")]
        public Input<Inputs.FsuCycleUpgradeDetailsGetArgs>? UpgradeDetails { get; set; }

        public FsuCycleState()
        {
        }
        public static new FsuCycleState Empty => new FsuCycleState();
    }
}
