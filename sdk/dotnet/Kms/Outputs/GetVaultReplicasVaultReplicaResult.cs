// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class GetVaultReplicasVaultReplicaResult
    {
        /// <summary>
        /// The vault replica's crypto endpoint
        /// </summary>
        public readonly string CryptoEndpoint;
        /// <summary>
        /// The vault replica's management endpoint
        /// </summary>
        public readonly string ManagementEndpoint;
        /// <summary>
        /// Region to which vault is replicated to
        /// </summary>
        public readonly string Region;
        /// <summary>
        /// Status of the Vault
        /// </summary>
        public readonly string Status;

        [OutputConstructor]
        private GetVaultReplicasVaultReplicaResult(
            string cryptoEndpoint,

            string managementEndpoint,

            string region,

            string status)
        {
            CryptoEndpoint = cryptoEndpoint;
            ManagementEndpoint = managementEndpoint;
            Region = region;
            Status = status;
        }
    }
}
