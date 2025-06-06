// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Outputs
{

    [OutputType]
    public sealed class RecommendationSupportedLevel
    {
        /// <summary>
        /// The list of supported levels.
        /// </summary>
        public readonly ImmutableArray<Outputs.RecommendationSupportedLevelItem> Items;

        [OutputConstructor]
        private RecommendationSupportedLevel(ImmutableArray<Outputs.RecommendationSupportedLevelItem> items)
        {
            Items = items;
        }
    }
}
