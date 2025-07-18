// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Maintenance Run resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates a maintenance run with one of the following:
    /// The latest available release update patch (RUP) for the Autonomous Container Database.
    /// The latest available RUP and DST time zone (TZ) file updates for the Autonomous Container Database.
    /// Creates a maintenance run to update the DST TZ file for the Autonomous Container Database.
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
    ///     var testMaintenanceRun = new Oci.Database.MaintenanceRun("test_maintenance_run", new()
    ///     {
    ///         PatchType = maintenanceRunPatchType,
    ///         TargetResourceId = testResource.Id,
    ///         TimeScheduled = maintenanceRunTimeScheduled,
    ///         CompartmentId = compartmentId,
    ///         DatabaseSoftwareImageId = testDatabaseSoftwareImage.Id,
    ///         IsDstFileUpdateEnabled = maintenanceRunIsDstFileUpdateEnabled,
    ///         PatchingMode = maintenanceRunPatchingMode,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// MaintenanceRuns can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Database/maintenanceRun:MaintenanceRun test_maintenance_run "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/maintenanceRun:MaintenanceRun")]
    public partial class MaintenanceRun : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Maintenance Run.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Extend current custom action timeout between the current database servers during waiting state, from 0 (zero) to 30 minutes.
        /// </summary>
        [Output("currentCustomActionTimeoutInMins")]
        public Output<int> CurrentCustomActionTimeoutInMins { get; private set; } = null!;

        /// <summary>
        /// The name of the current infrastruture component that is getting patched.
        /// </summary>
        [Output("currentPatchingComponent")]
        public Output<string> CurrentPatchingComponent { get; private set; } = null!;

        /// <summary>
        /// Determines the amount of time the system will wait before the start of each database server patching operation. Specify a number of minutes, from 15 to 120.
        /// </summary>
        [Output("customActionTimeoutInMins")]
        public Output<int> CustomActionTimeoutInMins { get; private set; } = null!;

        /// <summary>
        /// The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Output("databaseSoftwareImageId")]
        public Output<string> DatabaseSoftwareImageId { get; private set; } = null!;

        /// <summary>
        /// Description of the maintenance run.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the maintenance run.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The estimated start time of the next infrastruture component patching operation.
        /// </summary>
        [Output("estimatedComponentPatchingStartTime")]
        public Output<string> EstimatedComponentPatchingStartTime { get; private set; } = null!;

        /// <summary>
        /// The estimated total time required in minutes for all patching operations (database server, storage server, and network switch patching).
        /// </summary>
        [Output("estimatedPatchingTimes")]
        public Output<ImmutableArray<Outputs.MaintenanceRunEstimatedPatchingTime>> EstimatedPatchingTimes { get; private set; } = null!;

        /// <summary>
        /// If true, enables the configuration of a custom action timeout (waiting period) between database servers patching operations.
        /// </summary>
        [Output("isCustomActionTimeoutEnabled")]
        public Output<bool> IsCustomActionTimeoutEnabled { get; private set; } = null!;

        /// <summary>
        /// Indicates if an automatic DST Time Zone file update is enabled for the Autonomous Container Database. If enabled along with Release Update, patching will be done in a Non-Rolling manner.
        /// </summary>
        [Output("isDstFileUpdateEnabled")]
        public Output<bool> IsDstFileUpdateEnabled { get; private set; } = null!;

        /// <summary>
        /// If `FALSE`, the maintenance run doesn't support granular maintenance.
        /// </summary>
        [Output("isMaintenanceRunGranular")]
        public Output<bool> IsMaintenanceRunGranular { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// Maintenance sub-type.
        /// </summary>
        [Output("maintenanceSubtype")]
        public Output<string> MaintenanceSubtype { get; private set; } = null!;

        /// <summary>
        /// Maintenance type.
        /// </summary>
        [Output("maintenanceType")]
        public Output<string> MaintenanceType { get; private set; } = null!;

        /// <summary>
        /// Contain the patch failure count.
        /// </summary>
        [Output("patchFailureCount")]
        public Output<int> PatchFailureCount { get; private set; } = null!;

        /// <summary>
        /// The unique identifier of the patch. The identifier string includes the patch type, the Oracle Database version, and the patch creation date (using the format YYMMDD). For example, the identifier `ru_patch_19.9.0.0_201030` is used for an RU patch for Oracle Database 19.9.0.0 that was released October 30, 2020.
        /// </summary>
        [Output("patchId")]
        public Output<string> PatchId { get; private set; } = null!;

        /// <summary>
        /// Patch type, either "QUARTERLY", "TIMEZONE" or "CUSTOM_DATABASE_SOFTWARE_IMAGE".
        /// </summary>
        [Output("patchType")]
        public Output<string> PatchType { get; private set; } = null!;

        /// <summary>
        /// The time when the patching operation ended.
        /// </summary>
        [Output("patchingEndTime")]
        public Output<string> PatchingEndTime { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
        /// 
        /// *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
        /// </summary>
        [Output("patchingMode")]
        public Output<string> PatchingMode { get; private set; } = null!;

        /// <summary>
        /// The time when the patching operation started.
        /// </summary>
        [Output("patchingStartTime")]
        public Output<string> PatchingStartTime { get; private set; } = null!;

        /// <summary>
        /// The status of the patching operation.
        /// </summary>
        [Output("patchingStatus")]
        public Output<string> PatchingStatus { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
        /// </summary>
        [Output("peerMaintenanceRunId")]
        public Output<string> PeerMaintenanceRunId { get; private set; } = null!;

        /// <summary>
        /// The list of OCIDs for the maintenance runs associated with their Autonomous Data Guard peer container databases.
        /// </summary>
        [Output("peerMaintenanceRunIds")]
        public Output<ImmutableArray<string>> PeerMaintenanceRunIds { get; private set; } = null!;

        /// <summary>
        /// The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The target software version for the database server patching operation.
        /// </summary>
        [Output("targetDbServerVersion")]
        public Output<string> TargetDbServerVersion { get; private set; } = null!;

        /// <summary>
        /// The ID of the target resource for which the maintenance run should be created.
        /// </summary>
        [Output("targetResourceId")]
        public Output<string> TargetResourceId { get; private set; } = null!;

        /// <summary>
        /// The type of the target resource on which the maintenance run occurs.
        /// </summary>
        [Output("targetResourceType")]
        public Output<string> TargetResourceType { get; private set; } = null!;

        /// <summary>
        /// The target Cell version that is to be patched to.
        /// </summary>
        [Output("targetStorageServerVersion")]
        public Output<string> TargetStorageServerVersion { get; private set; } = null!;

        /// <summary>
        /// The date and time the maintenance run was completed.
        /// </summary>
        [Output("timeEnded")]
        public Output<string> TimeEnded { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The date and time that update should be scheduled.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("timeScheduled")]
        public Output<string> TimeScheduled { get; private set; } = null!;

        /// <summary>
        /// The date and time the maintenance run starts.
        /// </summary>
        [Output("timeStarted")]
        public Output<string> TimeStarted { get; private set; } = null!;

        /// <summary>
        /// The total time taken by corresponding resource activity in minutes.
        /// </summary>
        [Output("totalTimeTakenInMins")]
        public Output<int> TotalTimeTakenInMins { get; private set; } = null!;


        /// <summary>
        /// Create a MaintenanceRun resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MaintenanceRun(string name, MaintenanceRunArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/maintenanceRun:MaintenanceRun", name, args ?? new MaintenanceRunArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MaintenanceRun(string name, Input<string> id, MaintenanceRunState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/maintenanceRun:MaintenanceRun", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing MaintenanceRun resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MaintenanceRun Get(string name, Input<string> id, MaintenanceRunState? state = null, CustomResourceOptions? options = null)
        {
            return new MaintenanceRun(name, id, state, options);
        }
    }

    public sealed class MaintenanceRunArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Maintenance Run.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// Indicates if an automatic DST Time Zone file update is enabled for the Autonomous Container Database. If enabled along with Release Update, patching will be done in a Non-Rolling manner.
        /// </summary>
        [Input("isDstFileUpdateEnabled")]
        public Input<bool>? IsDstFileUpdateEnabled { get; set; }

        /// <summary>
        /// Patch type, either "QUARTERLY", "TIMEZONE" or "CUSTOM_DATABASE_SOFTWARE_IMAGE".
        /// </summary>
        [Input("patchType", required: true)]
        public Input<string> PatchType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
        /// 
        /// *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
        /// </summary>
        [Input("patchingMode")]
        public Input<string>? PatchingMode { get; set; }

        /// <summary>
        /// The ID of the target resource for which the maintenance run should be created.
        /// </summary>
        [Input("targetResourceId", required: true)]
        public Input<string> TargetResourceId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The date and time that update should be scheduled.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeScheduled", required: true)]
        public Input<string> TimeScheduled { get; set; } = null!;

        public MaintenanceRunArgs()
        {
        }
        public static new MaintenanceRunArgs Empty => new MaintenanceRunArgs();
    }

    public sealed class MaintenanceRunState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Maintenance Run.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Extend current custom action timeout between the current database servers during waiting state, from 0 (zero) to 30 minutes.
        /// </summary>
        [Input("currentCustomActionTimeoutInMins")]
        public Input<int>? CurrentCustomActionTimeoutInMins { get; set; }

        /// <summary>
        /// The name of the current infrastruture component that is getting patched.
        /// </summary>
        [Input("currentPatchingComponent")]
        public Input<string>? CurrentPatchingComponent { get; set; }

        /// <summary>
        /// Determines the amount of time the system will wait before the start of each database server patching operation. Specify a number of minutes, from 15 to 120.
        /// </summary>
        [Input("customActionTimeoutInMins")]
        public Input<int>? CustomActionTimeoutInMins { get; set; }

        /// <summary>
        /// The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// Description of the maintenance run.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The user-friendly name for the maintenance run.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The estimated start time of the next infrastruture component patching operation.
        /// </summary>
        [Input("estimatedComponentPatchingStartTime")]
        public Input<string>? EstimatedComponentPatchingStartTime { get; set; }

        [Input("estimatedPatchingTimes")]
        private InputList<Inputs.MaintenanceRunEstimatedPatchingTimeGetArgs>? _estimatedPatchingTimes;

        /// <summary>
        /// The estimated total time required in minutes for all patching operations (database server, storage server, and network switch patching).
        /// </summary>
        public InputList<Inputs.MaintenanceRunEstimatedPatchingTimeGetArgs> EstimatedPatchingTimes
        {
            get => _estimatedPatchingTimes ?? (_estimatedPatchingTimes = new InputList<Inputs.MaintenanceRunEstimatedPatchingTimeGetArgs>());
            set => _estimatedPatchingTimes = value;
        }

        /// <summary>
        /// If true, enables the configuration of a custom action timeout (waiting period) between database servers patching operations.
        /// </summary>
        [Input("isCustomActionTimeoutEnabled")]
        public Input<bool>? IsCustomActionTimeoutEnabled { get; set; }

        /// <summary>
        /// Indicates if an automatic DST Time Zone file update is enabled for the Autonomous Container Database. If enabled along with Release Update, patching will be done in a Non-Rolling manner.
        /// </summary>
        [Input("isDstFileUpdateEnabled")]
        public Input<bool>? IsDstFileUpdateEnabled { get; set; }

        /// <summary>
        /// If `FALSE`, the maintenance run doesn't support granular maintenance.
        /// </summary>
        [Input("isMaintenanceRunGranular")]
        public Input<bool>? IsMaintenanceRunGranular { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// Maintenance sub-type.
        /// </summary>
        [Input("maintenanceSubtype")]
        public Input<string>? MaintenanceSubtype { get; set; }

        /// <summary>
        /// Maintenance type.
        /// </summary>
        [Input("maintenanceType")]
        public Input<string>? MaintenanceType { get; set; }

        /// <summary>
        /// Contain the patch failure count.
        /// </summary>
        [Input("patchFailureCount")]
        public Input<int>? PatchFailureCount { get; set; }

        /// <summary>
        /// The unique identifier of the patch. The identifier string includes the patch type, the Oracle Database version, and the patch creation date (using the format YYMMDD). For example, the identifier `ru_patch_19.9.0.0_201030` is used for an RU patch for Oracle Database 19.9.0.0 that was released October 30, 2020.
        /// </summary>
        [Input("patchId")]
        public Input<string>? PatchId { get; set; }

        /// <summary>
        /// Patch type, either "QUARTERLY", "TIMEZONE" or "CUSTOM_DATABASE_SOFTWARE_IMAGE".
        /// </summary>
        [Input("patchType")]
        public Input<string>? PatchType { get; set; }

        /// <summary>
        /// The time when the patching operation ended.
        /// </summary>
        [Input("patchingEndTime")]
        public Input<string>? PatchingEndTime { get; set; }

        /// <summary>
        /// (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
        /// 
        /// *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
        /// </summary>
        [Input("patchingMode")]
        public Input<string>? PatchingMode { get; set; }

        /// <summary>
        /// The time when the patching operation started.
        /// </summary>
        [Input("patchingStartTime")]
        public Input<string>? PatchingStartTime { get; set; }

        /// <summary>
        /// The status of the patching operation.
        /// </summary>
        [Input("patchingStatus")]
        public Input<string>? PatchingStatus { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
        /// </summary>
        [Input("peerMaintenanceRunId")]
        public Input<string>? PeerMaintenanceRunId { get; set; }

        [Input("peerMaintenanceRunIds")]
        private InputList<string>? _peerMaintenanceRunIds;

        /// <summary>
        /// The list of OCIDs for the maintenance runs associated with their Autonomous Data Guard peer container databases.
        /// </summary>
        public InputList<string> PeerMaintenanceRunIds
        {
            get => _peerMaintenanceRunIds ?? (_peerMaintenanceRunIds = new InputList<string>());
            set => _peerMaintenanceRunIds = value;
        }

        /// <summary>
        /// The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The target software version for the database server patching operation.
        /// </summary>
        [Input("targetDbServerVersion")]
        public Input<string>? TargetDbServerVersion { get; set; }

        /// <summary>
        /// The ID of the target resource for which the maintenance run should be created.
        /// </summary>
        [Input("targetResourceId")]
        public Input<string>? TargetResourceId { get; set; }

        /// <summary>
        /// The type of the target resource on which the maintenance run occurs.
        /// </summary>
        [Input("targetResourceType")]
        public Input<string>? TargetResourceType { get; set; }

        /// <summary>
        /// The target Cell version that is to be patched to.
        /// </summary>
        [Input("targetStorageServerVersion")]
        public Input<string>? TargetStorageServerVersion { get; set; }

        /// <summary>
        /// The date and time the maintenance run was completed.
        /// </summary>
        [Input("timeEnded")]
        public Input<string>? TimeEnded { get; set; }

        /// <summary>
        /// (Updatable) The date and time that update should be scheduled.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeScheduled")]
        public Input<string>? TimeScheduled { get; set; }

        /// <summary>
        /// The date and time the maintenance run starts.
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        /// <summary>
        /// The total time taken by corresponding resource activity in minutes.
        /// </summary>
        [Input("totalTimeTakenInMins")]
        public Input<int>? TotalTimeTakenInMins { get; set; }

        public MaintenanceRunState()
        {
        }
        public static new MaintenanceRunState Empty => new MaintenanceRunState();
    }
}
