// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetComputeClustersComputeClusterCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetComputeClustersComputeClusterCollectionItemResult> Items;

        [OutputConstructor]
        private GetComputeClustersComputeClusterCollectionResult(ImmutableArray<Outputs.GetComputeClustersComputeClusterCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
