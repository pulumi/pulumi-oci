// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Outputs
{

    [OutputType]
    public sealed class GetAgentDataSourcesDataSourceCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetAgentDataSourcesDataSourceCollectionItemResult> Items;

        [OutputConstructor]
        private GetAgentDataSourcesDataSourceCollectionResult(ImmutableArray<Outputs.GetAgentDataSourcesDataSourceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
