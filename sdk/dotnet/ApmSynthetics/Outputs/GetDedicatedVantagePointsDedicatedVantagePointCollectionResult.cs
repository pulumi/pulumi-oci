// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class GetDedicatedVantagePointsDedicatedVantagePointCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDedicatedVantagePointsDedicatedVantagePointCollectionItemResult> Items;

        [OutputConstructor]
        private GetDedicatedVantagePointsDedicatedVantagePointCollectionResult(ImmutableArray<Outputs.GetDedicatedVantagePointsDedicatedVantagePointCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
