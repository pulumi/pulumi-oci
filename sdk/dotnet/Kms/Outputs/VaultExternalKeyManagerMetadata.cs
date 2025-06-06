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
    public sealed class VaultExternalKeyManagerMetadata
    {
        /// <summary>
        /// URI of the vault on external key manager.
        /// </summary>
        public readonly string ExternalVaultEndpointUrl;
        /// <summary>
        /// Authorization details required to get access token from IDP for accessing protected resources.
        /// </summary>
        public readonly Outputs.VaultExternalKeyManagerMetadataOauthMetadata OauthMetadata;
        /// <summary>
        /// OCID of private endpoint created by customer.
        /// </summary>
        public readonly string PrivateEndpointId;

        [OutputConstructor]
        private VaultExternalKeyManagerMetadata(
            string externalVaultEndpointUrl,

            Outputs.VaultExternalKeyManagerMetadataOauthMetadata oauthMetadata,

            string privateEndpointId)
        {
            ExternalVaultEndpointUrl = externalVaultEndpointUrl;
            OauthMetadata = oauthMetadata;
            PrivateEndpointId = privateEndpointId;
        }
    }
}
