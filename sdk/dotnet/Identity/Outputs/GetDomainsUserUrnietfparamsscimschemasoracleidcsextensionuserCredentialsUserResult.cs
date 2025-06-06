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
    public sealed class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserResult
    {
        /// <summary>
        /// A list of API keys corresponding to user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyResult> ApiKeys;
        /// <summary>
        /// A list of Auth tokens corresponding to user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthTokenResult> AuthTokens;
        /// <summary>
        /// A list of customer secret keys corresponding to user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyResult> CustomerSecretKeys;
        /// <summary>
        /// A list of database credentials corresponding to user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredentialResult> DbCredentials;
        /// <summary>
        /// A list of OAuth2 client credentials corresponding to a user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredentialResult> OAuth2clientCredentials;
        /// <summary>
        /// A list of SMTP credentials corresponding to user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredentialResult> SmtpCredentials;

        [OutputConstructor]
        private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserResult(
            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyResult> apiKeys,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthTokenResult> authTokens,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyResult> customerSecretKeys,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredentialResult> dbCredentials,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredentialResult> oAuth2clientCredentials,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredentialResult> smtpCredentials)
        {
            ApiKeys = apiKeys;
            AuthTokens = authTokens;
            CustomerSecretKeys = customerSecretKeys;
            DbCredentials = dbCredentials;
            OAuth2clientCredentials = oAuth2clientCredentials;
            SmtpCredentials = smtpCredentials;
        }
    }
}
