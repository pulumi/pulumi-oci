// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class GetVaultExternalKeyManagerMetadataSummaryResult
    {
        /// <summary>
        /// URL of the vault on external key manager.
        /// </summary>
        public readonly string ExternalVaultEndpointUrl;
        /// <summary>
        /// Summary about authorization to be returned to the customer as a response.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryResult> OauthMetadataSummaries;
        /// <summary>
        /// OCID of the private endpoint.
        /// </summary>
        public readonly string PrivateEndpointId;
        /// <summary>
        /// Vendor of the external key manager.
        /// </summary>
        public readonly string Vendor;

        [OutputConstructor]
        private GetVaultExternalKeyManagerMetadataSummaryResult(
            string externalVaultEndpointUrl,

            ImmutableArray<Outputs.GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryResult> oauthMetadataSummaries,

            string privateEndpointId,

            string vendor)
        {
            ExternalVaultEndpointUrl = externalVaultEndpointUrl;
            OauthMetadataSummaries = oauthMetadataSummaries;
            PrivateEndpointId = privateEndpointId;
            Vendor = vendor;
        }
    }
}