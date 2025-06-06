// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionResult
    {
        /// <summary>
        /// The details in the SQL tuning set summary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionItemResult> Items;

        [OutputConstructor]
        private GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionResult(ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
