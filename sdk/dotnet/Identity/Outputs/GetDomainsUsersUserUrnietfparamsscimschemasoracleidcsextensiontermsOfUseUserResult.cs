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
    public sealed class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserResult
    {
        /// <summary>
        /// Description:
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsentResult> TermsOfUseConsents;

        [OutputConstructor]
        private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserResult(ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsentResult> termsOfUseConsents)
        {
            TermsOfUseConsents = termsOfUseConsents;
        }
    }
}
