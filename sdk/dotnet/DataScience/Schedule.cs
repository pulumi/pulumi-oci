// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    /// <summary>
    /// This resource provides the Schedule resource in Oracle Cloud Infrastructure Data Science service.
    /// 
    /// Creates a new Schedule.
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
    ///     var testSchedule = new Oci.DataScience.Schedule("test_schedule", new()
    ///     {
    ///         Action = new Oci.DataScience.Inputs.ScheduleActionArgs
    ///         {
    ///             ActionDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsArgs
    ///             {
    ///                 HttpActionType = scheduleActionActionDetailsHttpActionType,
    ///                 CreateJobRunDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreateJobRunDetailsArgs
    ///                 {
    ///                     CompartmentId = compartmentId,
    ///                     DefinedTags = 
    ///                     {
    ///                         { "Operations.CostCenter", "42" },
    ///                     },
    ///                     DisplayName = scheduleActionActionDetailsCreateJobRunDetailsDisplayName,
    ///                     FreeformTags = 
    ///                     {
    ///                         { "Department", "Finance" },
    ///                     },
    ///                     JobConfigurationOverrideDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreateJobRunDetailsJobConfigurationOverrideDetailsArgs
    ///                     {
    ///                         JobType = scheduleActionActionDetailsCreateJobRunDetailsJobConfigurationOverrideDetailsJobType,
    ///                         CommandLineArguments = scheduleActionActionDetailsCreateJobRunDetailsJobConfigurationOverrideDetailsCommandLineArguments,
    ///                         EnvironmentVariables = scheduleActionActionDetailsCreateJobRunDetailsJobConfigurationOverrideDetailsEnvironmentVariables,
    ///                         MaximumRuntimeInMinutes = scheduleActionActionDetailsCreateJobRunDetailsJobConfigurationOverrideDetailsMaximumRuntimeInMinutes,
    ///                     },
    ///                     JobEnvironmentConfigurationOverrideDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsArgs
    ///                     {
    ///                         Image = scheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsImage,
    ///                         JobEnvironmentType = scheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsJobEnvironmentType,
    ///                         Cmds = scheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsCmd,
    ///                         Entrypoints = scheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsEntrypoint,
    ///                         ImageDigest = scheduleActionActionDetailsCreateJobRunDetailsJobEnvironmentConfigurationOverrideDetailsImageDigest,
    ///                         ImageSignatureId = testImageSignature.Id,
    ///                     },
    ///                     JobId = testJob.Id,
    ///                     JobLogConfigurationOverrideDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreateJobRunDetailsJobLogConfigurationOverrideDetailsArgs
    ///                     {
    ///                         EnableAutoLogCreation = scheduleActionActionDetailsCreateJobRunDetailsJobLogConfigurationOverrideDetailsEnableAutoLogCreation,
    ///                         EnableLogging = scheduleActionActionDetailsCreateJobRunDetailsJobLogConfigurationOverrideDetailsEnableLogging,
    ///                         LogGroupId = testLogGroup.Id,
    ///                         LogId = testLog.Id,
    ///                     },
    ///                     ProjectId = testProject.Id,
    ///                 },
    ///                 CreatePipelineRunDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsArgs
    ///                 {
    ///                     CompartmentId = compartmentId,
    ///                     ConfigurationOverrideDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsConfigurationOverrideDetailsArgs
    ///                     {
    ///                         Type = scheduleActionActionDetailsCreatePipelineRunDetailsConfigurationOverrideDetailsType,
    ///                         CommandLineArguments = scheduleActionActionDetailsCreatePipelineRunDetailsConfigurationOverrideDetailsCommandLineArguments,
    ///                         EnvironmentVariables = scheduleActionActionDetailsCreatePipelineRunDetailsConfigurationOverrideDetailsEnvironmentVariables,
    ///                         MaximumRuntimeInMinutes = scheduleActionActionDetailsCreatePipelineRunDetailsConfigurationOverrideDetailsMaximumRuntimeInMinutes,
    ///                     },
    ///                     DefinedTags = 
    ///                     {
    ///                         { "Operations.CostCenter", "42" },
    ///                     },
    ///                     DisplayName = scheduleActionActionDetailsCreatePipelineRunDetailsDisplayName,
    ///                     FreeformTags = 
    ///                     {
    ///                         { "Department", "Finance" },
    ///                     },
    ///                     LogConfigurationOverrideDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsLogConfigurationOverrideDetailsArgs
    ///                     {
    ///                         EnableAutoLogCreation = scheduleActionActionDetailsCreatePipelineRunDetailsLogConfigurationOverrideDetailsEnableAutoLogCreation,
    ///                         EnableLogging = scheduleActionActionDetailsCreatePipelineRunDetailsLogConfigurationOverrideDetailsEnableLogging,
    ///                         LogGroupId = testLogGroup.Id,
    ///                         LogId = testLog.Id,
    ///                     },
    ///                     PipelineId = testPipeline.Id,
    ///                     ProjectId = testProject.Id,
    ///                     StepOverrideDetails = new[]
    ///                     {
    ///                         new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailArgs
    ///                         {
    ///                             StepConfigurationDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailStepConfigurationDetailsArgs
    ///                             {
    ///                                 CommandLineArguments = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepConfigurationDetailsCommandLineArguments,
    ///                                 EnvironmentVariables = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepConfigurationDetailsEnvironmentVariables,
    ///                                 MaximumRuntimeInMinutes = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepConfigurationDetailsMaximumRuntimeInMinutes,
    ///                             },
    ///                             StepContainerConfigurationDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailStepContainerConfigurationDetailsArgs
    ///                             {
    ///                                 ContainerType = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepContainerConfigurationDetailsContainerType,
    ///                                 Image = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepContainerConfigurationDetailsImage,
    ///                                 Cmds = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepContainerConfigurationDetailsCmd,
    ///                                 Entrypoints = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepContainerConfigurationDetailsEntrypoint,
    ///                                 ImageDigest = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepContainerConfigurationDetailsImageDigest,
    ///                                 ImageSignatureId = testImageSignature.Id,
    ///                             },
    ///                             StepName = scheduleActionActionDetailsCreatePipelineRunDetailsStepOverrideDetailsStepName,
    ///                         },
    ///                     },
    ///                     SystemTags = scheduleActionActionDetailsCreatePipelineRunDetailsSystemTags,
    ///                 },
    ///                 MlApplicationInstanceViewId = testView.Id,
    ///                 TriggerMlApplicationInstanceViewFlowDetails = new Oci.DataScience.Inputs.ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetailsArgs
    ///                 {
    ///                     Parameters = new[]
    ///                     {
    ///                         new Oci.DataScience.Inputs.ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetailsParameterArgs
    ///                         {
    ///                             Name = scheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetailsParametersName,
    ///                             Value = scheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetailsParametersValue,
    ///                         },
    ///                     },
    ///                     TriggerName = testTrigger.Name,
    ///                 },
    ///             },
    ///             ActionType = scheduleActionActionType,
    ///         },
    ///         CompartmentId = compartmentId,
    ///         DisplayName = scheduleDisplayName,
    ///         ProjectId = testProject.Id,
    ///         Trigger = new Oci.DataScience.Inputs.ScheduleTriggerArgs
    ///         {
    ///             TriggerType = scheduleTriggerTriggerType,
    ///             CronExpression = scheduleTriggerCronExpression,
    ///             Frequency = scheduleTriggerFrequency,
    ///             Interval = scheduleTriggerInterval,
    ///             IsRandomStartTime = scheduleTriggerIsRandomStartTime,
    ///             Recurrence = scheduleTriggerRecurrence,
    ///             TimeEnd = scheduleTriggerTimeEnd,
    ///             TimeStart = scheduleTriggerTimeStart,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = scheduleDescription,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         LogDetails = new Oci.DataScience.Inputs.ScheduleLogDetailsArgs
    ///         {
    ///             LogGroupId = testLogGroup.Id,
    ///             LogId = testLog.Id,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Schedules can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DataScience/schedule:Schedule test_schedule "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataScience/schedule:Schedule")]
    public partial class Schedule : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The schedule action
        /// </summary>
        [Output("action")]
        public Output<Outputs.ScheduleAction> Action { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
        /// </summary>
        [Output("createdBy")]
        public Output<string> CreatedBy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A short description of the schedule.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
        /// </summary>
        [Output("lastScheduleRunDetails")]
        public Output<string> LastScheduleRunDetails { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Custom logging details for schedule execution.
        /// </summary>
        [Output("logDetails")]
        public Output<Outputs.ScheduleLogDetails?> LogDetails { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The current state of the schedule.           Example: `ACTIVE`
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Output("timeLastScheduleRun")]
        public Output<string> TimeLastScheduleRun { get; private set; } = null!;

        /// <summary>
        /// The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Output("timeNextScheduledRun")]
        public Output<string> TimeNextScheduledRun { get; private set; } = null!;

        /// <summary>
        /// The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
        /// </summary>
        [Output("trigger")]
        public Output<Outputs.ScheduleTrigger> Trigger { get; private set; } = null!;


        /// <summary>
        /// Create a Schedule resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Schedule(string name, ScheduleArgs args, CustomResourceOptions? options = null)
            : base("oci:DataScience/schedule:Schedule", name, args ?? new ScheduleArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Schedule(string name, Input<string> id, ScheduleState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataScience/schedule:Schedule", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Schedule resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Schedule Get(string name, Input<string> id, ScheduleState? state = null, CustomResourceOptions? options = null)
        {
            return new Schedule(name, id, state, options);
        }
    }

    public sealed class ScheduleArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The schedule action
        /// </summary>
        [Input("action", required: true)]
        public Input<Inputs.ScheduleActionArgs> Action { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the schedule.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Custom logging details for schedule execution.
        /// </summary>
        [Input("logDetails")]
        public Input<Inputs.ScheduleLogDetailsArgs>? LogDetails { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
        /// </summary>
        [Input("trigger", required: true)]
        public Input<Inputs.ScheduleTriggerArgs> Trigger { get; set; } = null!;

        public ScheduleArgs()
        {
        }
        public static new ScheduleArgs Empty => new ScheduleArgs();
    }

    public sealed class ScheduleState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The schedule action
        /// </summary>
        [Input("action")]
        public Input<Inputs.ScheduleActionGetArgs>? Action { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
        /// </summary>
        [Input("createdBy")]
        public Input<string>? CreatedBy { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the schedule.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
        /// </summary>
        [Input("lastScheduleRunDetails")]
        public Input<string>? LastScheduleRunDetails { get; set; }

        /// <summary>
        /// A message describing the current state in more detail.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Custom logging details for schedule execution.
        /// </summary>
        [Input("logDetails")]
        public Input<Inputs.ScheduleLogDetailsGetArgs>? LogDetails { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The current state of the schedule.           Example: `ACTIVE`
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
        /// The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Input("timeLastScheduleRun")]
        public Input<string>? TimeLastScheduleRun { get; set; }

        /// <summary>
        /// The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
        /// </summary>
        [Input("timeNextScheduledRun")]
        public Input<string>? TimeNextScheduledRun { get; set; }

        /// <summary>
        /// The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
        /// </summary>
        [Input("trigger")]
        public Input<Inputs.ScheduleTriggerGetArgs>? Trigger { get; set; }

        public ScheduleState()
        {
        }
        public static new ScheduleState Empty => new ScheduleState();
    }
}
