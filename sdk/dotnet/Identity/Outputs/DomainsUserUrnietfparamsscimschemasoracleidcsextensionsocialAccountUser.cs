// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionsocialAccountUser
    {
        /// <summary>
        /// (Updatable) Description:
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionsocialAccountUserSocialAccount> SocialAccounts;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsocialAccountUser(ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionsocialAccountUserSocialAccount> socialAccounts)
        {
            SocialAccounts = socialAccounts;
        }
    }
}