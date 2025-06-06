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
    public sealed class GetBuildPipelineStagesBuildPipelineStageCollectionResult
    {
        /// <summary>
        /// Collection of artifacts that were generated in the Build stage and need to be pushed to the artifactory stores. In case of UPDATE operation, replaces existing artifacts list. Merging with existing artifacts is not supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildPipelineStagesBuildPipelineStageCollectionItemResult> Items;

        [OutputConstructor]
        private GetBuildPipelineStagesBuildPipelineStageCollectionResult(ImmutableArray<Outputs.GetBuildPipelineStagesBuildPipelineStageCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
