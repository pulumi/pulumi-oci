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
    public sealed class GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemResult> Items;

        [OutputConstructor]
        private GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionResult(ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
