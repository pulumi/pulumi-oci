// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.VisualBuilder.Outputs
{

    [OutputType]
    public sealed class GetVbInstancesVbInstanceSummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetVbInstancesVbInstanceSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetVbInstancesVbInstanceSummaryCollectionResult(ImmutableArray<Outputs.GetVbInstancesVbInstanceSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
