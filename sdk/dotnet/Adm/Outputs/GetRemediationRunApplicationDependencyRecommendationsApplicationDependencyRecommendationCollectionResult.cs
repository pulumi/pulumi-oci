// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm.Outputs
{

    [OutputType]
    public sealed class GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionResult
    {
        /// <summary>
        /// List of application recommendation summaries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItemResult> Items;

        [OutputConstructor]
        private GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionResult(ImmutableArray<Outputs.GetRemediationRunApplicationDependencyRecommendationsApplicationDependencyRecommendationCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
