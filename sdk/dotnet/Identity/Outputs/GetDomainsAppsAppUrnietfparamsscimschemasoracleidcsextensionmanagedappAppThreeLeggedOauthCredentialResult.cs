// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredentialResult
    {
        /// <summary>
        /// Access Token
        /// </summary>
        public readonly string AccessToken;
        /// <summary>
        /// Access token expiry
        /// </summary>
        public readonly string AccessTokenExpiry;
        /// <summary>
        /// Refresh Token
        /// </summary>
        public readonly string RefreshToken;

        [OutputConstructor]
        private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredentialResult(
            string accessToken,

            string accessTokenExpiry,

            string refreshToken)
        {
            AccessToken = accessToken;
            AccessTokenExpiry = accessTokenExpiry;
            RefreshToken = refreshToken;
        }
    }
}
