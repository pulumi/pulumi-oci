// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationObjectTypesMigrationObjectTypeSummaryCollectionResult
    {
        /// <summary>
        /// Items in collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationObjectTypesMigrationObjectTypeSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetMigrationObjectTypesMigrationObjectTypeSummaryCollectionResult(ImmutableArray<Outputs.GetMigrationObjectTypesMigrationObjectTypeSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
