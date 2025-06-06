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
    public sealed class GetPipelineStepArtifactResult
    {
        public readonly string ArtifactContentDisposition;
        public readonly string ArtifactContentLength;
        public readonly string ArtifactContentMd5;
        public readonly string ArtifactLastModified;
        public readonly string PipelineStepArtifact;
        /// <summary>
        /// The name of the step. It must be unique within the pipeline. This is used to create the pipeline DAG.
        /// </summary>
        public readonly string StepName;

        [OutputConstructor]
        private GetPipelineStepArtifactResult(
            string artifactContentDisposition,

            string artifactContentLength,

            string artifactContentMd5,

            string artifactLastModified,

            string pipelineStepArtifact,

            string stepName)
        {
            ArtifactContentDisposition = artifactContentDisposition;
            ArtifactContentLength = artifactContentLength;
            ArtifactContentMd5 = artifactContentMd5;
            ArtifactLastModified = artifactLastModified;
            PipelineStepArtifact = pipelineStepArtifact;
            StepName = stepName;
        }
    }
}
