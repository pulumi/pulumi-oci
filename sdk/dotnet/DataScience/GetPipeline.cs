// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetPipeline
    {
        /// <summary>
        /// This data source provides details about a specific Pipeline resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a Pipeline by identifier.
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
        ///     var testPipeline = Oci.DataScience.GetPipeline.Invoke(new()
        ///     {
        ///         PipelineId = testPipelineOciDatasciencePipeline.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPipelineResult> InvokeAsync(GetPipelineArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPipelineResult>("oci:DataScience/getPipeline:getPipeline", args ?? new GetPipelineArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Pipeline resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a Pipeline by identifier.
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
        ///     var testPipeline = Oci.DataScience.GetPipeline.Invoke(new()
        ///     {
        ///         PipelineId = testPipelineOciDatasciencePipeline.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPipelineResult> Invoke(GetPipelineInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPipelineResult>("oci:DataScience/getPipeline:getPipeline", args ?? new GetPipelineInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Pipeline resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a Pipeline by identifier.
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
        ///     var testPipeline = Oci.DataScience.GetPipeline.Invoke(new()
        ///     {
        ///         PipelineId = testPipelineOciDatasciencePipeline.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPipelineResult> Invoke(GetPipelineInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPipelineResult>("oci:DataScience/getPipeline:getPipeline", args ?? new GetPipelineInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPipelineArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
        /// </summary>
        [Input("pipelineId", required: true)]
        public string PipelineId { get; set; } = null!;

        public GetPipelineArgs()
        {
        }
        public static new GetPipelineArgs Empty => new GetPipelineArgs();
    }

    public sealed class GetPipelineInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
        /// </summary>
        [Input("pipelineId", required: true)]
        public Input<string> PipelineId { get; set; } = null!;

        public GetPipelineInvokeArgs()
        {
        }
        public static new GetPipelineInvokeArgs Empty => new GetPipelineInvokeArgs();
    }


    [OutputType]
    public sealed class GetPipelineResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The configuration details of a pipeline.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineConfigurationDetailResult> ConfigurationDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// If set to true will delete pipeline runs which are in a terminal state.
        /// </summary>
        public readonly bool DeleteRelatedPipelineRuns;
        /// <summary>
        /// A short description of the step.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly display name for the resource.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The infrastructure configuration details of a pipeline or a step.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineInfrastructureConfigurationDetailResult> InfrastructureConfigurationDetails;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The pipeline log configuration details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineLogConfigurationDetailResult> LogConfigurationDetails;
        public readonly string PipelineId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The current state of the pipeline.
        /// </summary>
        public readonly string State;
        public readonly ImmutableArray<Outputs.GetPipelineStepArtifactResult> StepArtifacts;
        /// <summary>
        /// Array of step details for each step.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineStepDetailResult> StepDetails;
        /// <summary>
        /// The storage mount details to mount to the instance running the pipeline step.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineStorageMountConfigurationDetailsListResult> StorageMountConfigurationDetailsLists;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetPipelineResult(
            string compartmentId,

            ImmutableArray<Outputs.GetPipelineConfigurationDetailResult> configurationDetails,

            string createdBy,

            ImmutableDictionary<string, string> definedTags,

            bool deleteRelatedPipelineRuns,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetPipelineInfrastructureConfigurationDetailResult> infrastructureConfigurationDetails,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetPipelineLogConfigurationDetailResult> logConfigurationDetails,

            string pipelineId,

            string projectId,

            string state,

            ImmutableArray<Outputs.GetPipelineStepArtifactResult> stepArtifacts,

            ImmutableArray<Outputs.GetPipelineStepDetailResult> stepDetails,

            ImmutableArray<Outputs.GetPipelineStorageMountConfigurationDetailsListResult> storageMountConfigurationDetailsLists,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            ConfigurationDetails = configurationDetails;
            CreatedBy = createdBy;
            DefinedTags = definedTags;
            DeleteRelatedPipelineRuns = deleteRelatedPipelineRuns;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InfrastructureConfigurationDetails = infrastructureConfigurationDetails;
            LifecycleDetails = lifecycleDetails;
            LogConfigurationDetails = logConfigurationDetails;
            PipelineId = pipelineId;
            ProjectId = projectId;
            State = state;
            StepArtifacts = stepArtifacts;
            StepDetails = stepDetails;
            StorageMountConfigurationDetailsLists = storageMountConfigurationDetailsLists;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
