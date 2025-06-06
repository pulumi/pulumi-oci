// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceIdentityConfigurationUpstConfigurationDetailResult
    {
        /// <summary>
        /// Master Encryption key used for encrypting token exchange keytab.
        /// </summary>
        public readonly string MasterEncryptionKeyId;
        /// <summary>
        /// The instance OCID of the node, which is the resource from which the node backup was acquired.
        /// </summary>
        public readonly string VaultId;

        [OutputConstructor]
        private GetBdsInstanceIdentityConfigurationUpstConfigurationDetailResult(
            string masterEncryptionKeyId,

            string vaultId)
        {
            MasterEncryptionKeyId = masterEncryptionKeyId;
            VaultId = vaultId;
        }
    }
}
