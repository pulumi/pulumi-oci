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
    public sealed class GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildPipelineStagePredecessorCollectionItemResult
    {
        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildPipelineStagePredecessorCollectionItemResult(string id)
        {
            Id = id;
        }
    }
}
