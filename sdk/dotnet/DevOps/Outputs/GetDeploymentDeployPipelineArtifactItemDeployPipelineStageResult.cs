// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetDeploymentDeployPipelineArtifactItemDeployPipelineStageResult
    {
        /// <summary>
        /// A list of stage predecessors for a stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentDeployPipelineArtifactItemDeployPipelineStageItemResult> Items;

        [OutputConstructor]
        private GetDeploymentDeployPipelineArtifactItemDeployPipelineStageResult(ImmutableArray<Outputs.GetDeploymentDeployPipelineArtifactItemDeployPipelineStageItemResult> items)
        {
            Items = items;
        }
    }
}
