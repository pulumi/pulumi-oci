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
    /// This resource provides the Pipeline Run resource in Oracle Cloud Infrastructure Data Science service.
    /// 
    /// Creates a new PipelineRun.
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
    ///     var testPipelineRun = new Oci.DataScience.PipelineRun("test_pipeline_run", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         PipelineId = testPipeline.Id,
    ///         ConfigurationOverrideDetails = new Oci.DataScience.Inputs.PipelineRunConfigurationOverrideDetailsArgs
    ///         {
    ///             Type = pipelineRunConfigurationOverrideDetailsType,
    ///             CommandLineArguments = pipelineRunConfigurationOverrideDetailsCommandLineArguments,
    ///             EnvironmentVariables = pipelineRunConfigurationOverrideDetailsEnvironmentVariables,
    ///             MaximumRuntimeInMinutes = pipelineRunConfigurationOverrideDetailsMaximumRuntimeInMinutes,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         DisplayName = pipelineRunDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         LogConfigurationOverrideDetails = new Oci.DataScience.Inputs.PipelineRunLogConfigurationOverrideDetailsArgs
    ///         {
    ///             EnableAutoLogCreation = pipelineRunLogConfigurationOverrideDetailsEnableAutoLogCreation,
    ///             EnableLogging = pipelineRunLogConfigurationOverrideDetailsEnableLogging,
    ///             LogGroupId = testLogGroup.Id,
    ///             LogId = testLog.Id,
    ///         },
    ///         OpcParentRptUrl = pipelineRunOpcParentRptUrl,
    ///         ProjectId = testProject.Id,
    ///         StepOverrideDetails = new[]
    ///         {
    ///             new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailArgs
    ///             {
    ///                 StepConfigurationDetails = new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailStepConfigurationDetailsArgs
    ///                 {
    ///                     CommandLineArguments = pipelineRunStepOverrideDetailsStepConfigurationDetailsCommandLineArguments,
    ///                     EnvironmentVariables = pipelineRunStepOverrideDetailsStepConfigurationDetailsEnvironmentVariables,
    ///                     MaximumRuntimeInMinutes = pipelineRunStepOverrideDetailsStepConfigurationDetailsMaximumRuntimeInMinutes,
    ///                 },
    ///                 StepName = pipelineRunStepOverrideDetailsStepName,
    ///                 StepContainerConfigurationDetails = new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailStepContainerConfigurationDetailsArgs
    ///                 {
    ///                     ContainerType = pipelineRunStepOverrideDetailsStepContainerConfigurationDetailsContainerType,
    ///                     Image = pipelineRunStepOverrideDetailsStepContainerConfigurationDetailsImage,
    ///                     Cmds = pipelineRunStepOverrideDetailsStepContainerConfigurationDetailsCmd,
    ///                     Entrypoints = pipelineRunStepOverrideDetailsStepContainerConfigurationDetailsEntrypoint,
    ///                     ImageDigest = pipelineRunStepOverrideDetailsStepContainerConfigurationDetailsImageDigest,
    ///                     ImageSignatureId = testImageSignature.Id,
    ///                 },
    ///                 StepDataflowConfigurationDetails = new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailStepDataflowConfigurationDetailsArgs
    ///                 {
    ///                     Configuration = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsConfiguration,
    ///                     DriverShape = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsDriverShape,
    ///                     DriverShapeConfigDetails = new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailStepDataflowConfigurationDetailsDriverShapeConfigDetailsArgs
    ///                     {
    ///                         MemoryInGbs = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsDriverShapeConfigDetailsMemoryInGbs,
    ///                         Ocpus = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsDriverShapeConfigDetailsOcpus,
    ///                     },
    ///                     ExecutorShape = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsExecutorShape,
    ///                     ExecutorShapeConfigDetails = new Oci.DataScience.Inputs.PipelineRunStepOverrideDetailStepDataflowConfigurationDetailsExecutorShapeConfigDetailsArgs
    ///                     {
    ///                         MemoryInGbs = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsExecutorShapeConfigDetailsMemoryInGbs,
    ///                         Ocpus = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsExecutorShapeConfigDetailsOcpus,
    ///                     },
    ///                     LogsBucketUri = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsLogsBucketUri,
    ///                     NumExecutors = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsNumExecutors,
    ///                     WarehouseBucketUri = pipelineRunStepOverrideDetailsStepDataflowConfigurationDetailsWarehouseBucketUri,
    ///                 },
    ///             },
    ///         },
    ///         SystemTags = pipelineRunSystemTags,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// PipelineRuns can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DataScience/pipelineRun:PipelineRun test_pipeline_run "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataScience/pipelineRun:PipelineRun")]
    public partial class PipelineRun : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline run.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        [Output("configurationDetails")]
        public Output<ImmutableArray<Outputs.PipelineRunConfigurationDetail>> ConfigurationDetails { get; private set; } = null!;

        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        [Output("configurationOverrideDetails")]
        public Output<Outputs.PipelineRunConfigurationOverrideDetails> ConfigurationOverrideDetails { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline run.
        /// </summary>
        [Output("createdBy")]
        public Output<string> CreatedBy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        [Output("deleteRelatedJobRuns")]
        public Output<bool?> DeleteRelatedJobRuns { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Details of the state of the step run.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The pipeline log configuration details.
        /// </summary>
        [Output("logConfigurationOverrideDetails")]
        public Output<Outputs.PipelineRunLogConfigurationOverrideDetails> LogConfigurationOverrideDetails { get; private set; } = null!;

        /// <summary>
        /// Customer logging details for pipeline run.
        /// </summary>
        [Output("logDetails")]
        public Output<ImmutableArray<Outputs.PipelineRunLogDetail>> LogDetails { get; private set; } = null!;

        /// <summary>
        /// URL to fetch the Resource Principal Token from the parent resource.
        /// </summary>
        [Output("opcParentRptUrl")]
        public Output<string?> OpcParentRptUrl { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline for which pipeline run is created.
        /// </summary>
        [Output("pipelineId")]
        public Output<string> PipelineId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline run with.
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The state of the step run.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Array of step override details. Only Step Configuration is allowed to be overridden.
        /// </summary>
        [Output("stepOverrideDetails")]
        public Output<ImmutableArray<Outputs.PipelineRunStepOverrideDetail>> StepOverrideDetails { get; private set; } = null!;

        /// <summary>
        /// Array of StepRun object for each step.
        /// </summary>
        [Output("stepRuns")]
        public Output<ImmutableArray<Outputs.PipelineRunStepRun>> StepRuns { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the pipeline run was accepted in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeAccepted")]
        public Output<string> TimeAccepted { get; private set; } = null!;

        /// <summary>
        /// The date and time the pipeline run request was finished in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeFinished")]
        public Output<string> TimeFinished { get; private set; } = null!;

        /// <summary>
        /// The date and time the pipeline run request was started in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeStarted")]
        public Output<string> TimeStarted { get; private set; } = null!;

        /// <summary>
        /// The date and time the pipeline run was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a PipelineRun resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PipelineRun(string name, PipelineRunArgs args, CustomResourceOptions? options = null)
            : base("oci:DataScience/pipelineRun:PipelineRun", name, args ?? new PipelineRunArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PipelineRun(string name, Input<string> id, PipelineRunState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataScience/pipelineRun:PipelineRun", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PipelineRun resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PipelineRun Get(string name, Input<string> id, PipelineRunState? state = null, CustomResourceOptions? options = null)
        {
            return new PipelineRun(name, id, state, options);
        }
    }

    public sealed class PipelineRunArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline run.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        [Input("configurationOverrideDetails")]
        public Input<Inputs.PipelineRunConfigurationOverrideDetailsArgs>? ConfigurationOverrideDetails { get; set; }

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

        [Input("deleteRelatedJobRuns")]
        public Input<bool>? DeleteRelatedJobRuns { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource.
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
        /// The pipeline log configuration details.
        /// </summary>
        [Input("logConfigurationOverrideDetails")]
        public Input<Inputs.PipelineRunLogConfigurationOverrideDetailsArgs>? LogConfigurationOverrideDetails { get; set; }

        /// <summary>
        /// URL to fetch the Resource Principal Token from the parent resource.
        /// </summary>
        [Input("opcParentRptUrl")]
        public Input<string>? OpcParentRptUrl { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline for which pipeline run is created.
        /// </summary>
        [Input("pipelineId", required: true)]
        public Input<string> PipelineId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline run with.
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        [Input("stepOverrideDetails")]
        private InputList<Inputs.PipelineRunStepOverrideDetailArgs>? _stepOverrideDetails;

        /// <summary>
        /// Array of step override details. Only Step Configuration is allowed to be overridden.
        /// </summary>
        public InputList<Inputs.PipelineRunStepOverrideDetailArgs> StepOverrideDetails
        {
            get => _stepOverrideDetails ?? (_stepOverrideDetails = new InputList<Inputs.PipelineRunStepOverrideDetailArgs>());
            set => _stepOverrideDetails = value;
        }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        public PipelineRunArgs()
        {
        }
        public static new PipelineRunArgs Empty => new PipelineRunArgs();
    }

    public sealed class PipelineRunState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline run.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("configurationDetails")]
        private InputList<Inputs.PipelineRunConfigurationDetailGetArgs>? _configurationDetails;

        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        public InputList<Inputs.PipelineRunConfigurationDetailGetArgs> ConfigurationDetails
        {
            get => _configurationDetails ?? (_configurationDetails = new InputList<Inputs.PipelineRunConfigurationDetailGetArgs>());
            set => _configurationDetails = value;
        }

        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        [Input("configurationOverrideDetails")]
        public Input<Inputs.PipelineRunConfigurationOverrideDetailsGetArgs>? ConfigurationOverrideDetails { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline run.
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

        [Input("deleteRelatedJobRuns")]
        public Input<bool>? DeleteRelatedJobRuns { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource.
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
        /// Details of the state of the step run.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The pipeline log configuration details.
        /// </summary>
        [Input("logConfigurationOverrideDetails")]
        public Input<Inputs.PipelineRunLogConfigurationOverrideDetailsGetArgs>? LogConfigurationOverrideDetails { get; set; }

        [Input("logDetails")]
        private InputList<Inputs.PipelineRunLogDetailGetArgs>? _logDetails;

        /// <summary>
        /// Customer logging details for pipeline run.
        /// </summary>
        public InputList<Inputs.PipelineRunLogDetailGetArgs> LogDetails
        {
            get => _logDetails ?? (_logDetails = new InputList<Inputs.PipelineRunLogDetailGetArgs>());
            set => _logDetails = value;
        }

        /// <summary>
        /// URL to fetch the Resource Principal Token from the parent resource.
        /// </summary>
        [Input("opcParentRptUrl")]
        public Input<string>? OpcParentRptUrl { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline for which pipeline run is created.
        /// </summary>
        [Input("pipelineId")]
        public Input<string>? PipelineId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline run with.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The state of the step run.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("stepOverrideDetails")]
        private InputList<Inputs.PipelineRunStepOverrideDetailGetArgs>? _stepOverrideDetails;

        /// <summary>
        /// Array of step override details. Only Step Configuration is allowed to be overridden.
        /// </summary>
        public InputList<Inputs.PipelineRunStepOverrideDetailGetArgs> StepOverrideDetails
        {
            get => _stepOverrideDetails ?? (_stepOverrideDetails = new InputList<Inputs.PipelineRunStepOverrideDetailGetArgs>());
            set => _stepOverrideDetails = value;
        }

        [Input("stepRuns")]
        private InputList<Inputs.PipelineRunStepRunGetArgs>? _stepRuns;

        /// <summary>
        /// Array of StepRun object for each step.
        /// </summary>
        public InputList<Inputs.PipelineRunStepRunGetArgs> StepRuns
        {
            get => _stepRuns ?? (_stepRuns = new InputList<Inputs.PipelineRunStepRunGetArgs>());
            set => _stepRuns = value;
        }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the pipeline run was accepted in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeAccepted")]
        public Input<string>? TimeAccepted { get; set; }

        /// <summary>
        /// The date and time the pipeline run request was finished in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeFinished")]
        public Input<string>? TimeFinished { get; set; }

        /// <summary>
        /// The date and time the pipeline run request was started in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        /// <summary>
        /// The date and time the pipeline run was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public PipelineRunState()
        {
        }
        public static new PipelineRunState Empty => new PipelineRunState();
    }
}
