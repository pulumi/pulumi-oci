// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class PipelineStepDetail
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dataflow application to be used as a step.
        /// </summary>
        public readonly string? ApplicationId;
        /// <summary>
        /// The list of step names this current step depends on for execution.
        /// </summary>
        public readonly ImmutableArray<string> DependsOns;
        /// <summary>
        /// (Updatable) A short description of the step.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// A flag to indicate whether the artifact has been uploaded for this step or not.
        /// </summary>
        public readonly bool? IsArtifactUploaded;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job to be used as a step.
        /// </summary>
        public readonly string? JobId;
        /// <summary>
        /// (Updatable) The configuration details of a step.
        /// </summary>
        public readonly Outputs.PipelineStepDetailStepConfigurationDetails? StepConfigurationDetails;
        /// <summary>
        /// Container Details for a step in pipeline.
        /// </summary>
        public readonly Outputs.PipelineStepDetailStepContainerConfigurationDetails? StepContainerConfigurationDetails;
        /// <summary>
        /// (Updatable) The configuration details of a Dataflow step.
        /// </summary>
        public readonly Outputs.PipelineStepDetailStepDataflowConfigurationDetails? StepDataflowConfigurationDetails;
        /// <summary>
        /// (Updatable) The infrastructure configuration details of a pipeline or a step.
        /// </summary>
        public readonly Outputs.PipelineStepDetailStepInfrastructureConfigurationDetails? StepInfrastructureConfigurationDetails;
        /// <summary>
        /// (Updatable) The name of the step. It must be unique within the pipeline. This is used to create the pipeline DAG.
        /// </summary>
        public readonly string StepName;
        /// <summary>
        /// (Updatable) The storage mount details to mount to the instance running the pipeline step.
        /// </summary>
        public readonly ImmutableArray<Outputs.PipelineStepDetailStepStorageMountConfigurationDetailsList> StepStorageMountConfigurationDetailsLists;
        /// <summary>
        /// (Updatable) The type of step.
        /// </summary>
        public readonly string StepType;

        [OutputConstructor]
        private PipelineStepDetail(
            string? applicationId,

            ImmutableArray<string> dependsOns,

            string? description,

            bool? isArtifactUploaded,

            string? jobId,

            Outputs.PipelineStepDetailStepConfigurationDetails? stepConfigurationDetails,

            Outputs.PipelineStepDetailStepContainerConfigurationDetails? stepContainerConfigurationDetails,

            Outputs.PipelineStepDetailStepDataflowConfigurationDetails? stepDataflowConfigurationDetails,

            Outputs.PipelineStepDetailStepInfrastructureConfigurationDetails? stepInfrastructureConfigurationDetails,

            string stepName,

            ImmutableArray<Outputs.PipelineStepDetailStepStorageMountConfigurationDetailsList> stepStorageMountConfigurationDetailsLists,

            string stepType)
        {
            ApplicationId = applicationId;
            DependsOns = dependsOns;
            Description = description;
            IsArtifactUploaded = isArtifactUploaded;
            JobId = jobId;
            StepConfigurationDetails = stepConfigurationDetails;
            StepContainerConfigurationDetails = stepContainerConfigurationDetails;
            StepDataflowConfigurationDetails = stepDataflowConfigurationDetails;
            StepInfrastructureConfigurationDetails = stepInfrastructureConfigurationDetails;
            StepName = stepName;
            StepStorageMountConfigurationDetailsLists = stepStorageMountConfigurationDetailsLists;
            StepType = stepType;
        }
    }
}
