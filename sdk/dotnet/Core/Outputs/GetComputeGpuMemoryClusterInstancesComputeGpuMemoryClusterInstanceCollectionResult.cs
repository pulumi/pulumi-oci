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
    public sealed class GetComputeGpuMemoryClusterInstancesComputeGpuMemoryClusterInstanceCollectionResult
    {
        /// <summary>
        /// The list of compute GPU memory cluster instances.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeGpuMemoryClusterInstancesComputeGpuMemoryClusterInstanceCollectionItemResult> Items;

        [OutputConstructor]
        private GetComputeGpuMemoryClusterInstancesComputeGpuMemoryClusterInstanceCollectionResult(ImmutableArray<Outputs.GetComputeGpuMemoryClusterInstancesComputeGpuMemoryClusterInstanceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
