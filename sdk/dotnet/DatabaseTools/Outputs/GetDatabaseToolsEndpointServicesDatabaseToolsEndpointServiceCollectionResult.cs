// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools.Outputs
{

    [OutputType]
    public sealed class GetDatabaseToolsEndpointServicesDatabaseToolsEndpointServiceCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDatabaseToolsEndpointServicesDatabaseToolsEndpointServiceCollectionItemResult> Items;

        [OutputConstructor]
        private GetDatabaseToolsEndpointServicesDatabaseToolsEndpointServiceCollectionResult(ImmutableArray<Outputs.GetDatabaseToolsEndpointServicesDatabaseToolsEndpointServiceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
