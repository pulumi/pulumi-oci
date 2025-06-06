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
    public sealed class ConfigConfigurationDatabaseWalletDetails
    {
        /// <summary>
        /// (Updatable) The database wallet configuration zip file.
        /// </summary>
        public readonly string? DatabaseWallet;
        /// <summary>
        /// (Updatable) Service name of the database.
        /// </summary>
        public readonly string? ServiceName;

        [OutputConstructor]
        private ConfigConfigurationDatabaseWalletDetails(
            string? databaseWallet,

            string? serviceName)
        {
            DatabaseWallet = databaseWallet;
            ServiceName = serviceName;
        }
    }
}
