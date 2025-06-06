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
    public sealed class GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoResult
    {
        /// <summary>
        /// The component type.
        /// </summary>
        public readonly string ComponentType;
        /// <summary>
        /// The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoConnectionCredentialResult> ConnectionCredentials;
        /// <summary>
        /// The Oracle Database connection string.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoConnectionStringResult> ConnectionStrings;
        /// <summary>
        /// The credential to connect to the database to perform tablespace administration tasks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoDatabaseCredentialResult> DatabaseCredentials;

        [OutputConstructor]
        private GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoResult(
            string componentType,

            ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoConnectionCredentialResult> connectionCredentials,

            ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoConnectionStringResult> connectionStrings,

            ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentClusterInstanceConnectorConnectionInfoDatabaseCredentialResult> databaseCredentials)
        {
            ComponentType = componentType;
            ConnectionCredentials = connectionCredentials;
            ConnectionStrings = connectionStrings;
            DatabaseCredentials = databaseCredentials;
        }
    }
}
