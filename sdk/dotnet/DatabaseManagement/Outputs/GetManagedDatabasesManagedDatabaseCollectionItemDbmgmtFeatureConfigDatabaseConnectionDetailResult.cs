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
    public sealed class GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailResult
    {
        /// <summary>
        /// The credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredentialResult> ConnectionCredentials;
        /// <summary>
        /// The details of the Oracle Database connection string.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionStringResult> ConnectionStrings;

        [OutputConstructor]
        private GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailResult(
            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredentialResult> connectionCredentials,

            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionStringResult> connectionStrings)
        {
            ConnectionCredentials = connectionCredentials;
            ConnectionStrings = connectionStrings;
        }
    }
}
