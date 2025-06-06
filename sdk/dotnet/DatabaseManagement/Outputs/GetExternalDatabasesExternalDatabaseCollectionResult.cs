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
    public sealed class GetExternalDatabasesExternalDatabaseCollectionResult
    {
        /// <summary>
        /// An array of external databases.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemResult> Items;

        [OutputConstructor]
        private GetExternalDatabasesExternalDatabaseCollectionResult(ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
