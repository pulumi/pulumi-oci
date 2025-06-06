// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy.Outputs
{

    [OutputType]
    public sealed class GetSubscriptionRedeemableUsersRedeemableUserCollectionItemItemResult
    {
        /// <summary>
        /// The email ID of the user that can redeem rewards.
        /// </summary>
        public readonly string EmailId;
        /// <summary>
        /// The first name of the user that can redeem rewards.
        /// </summary>
        public readonly string FirstName;
        /// <summary>
        /// The last name of the user that can redeem rewards.
        /// </summary>
        public readonly string LastName;

        [OutputConstructor]
        private GetSubscriptionRedeemableUsersRedeemableUserCollectionItemItemResult(
            string emailId,

            string firstName,

            string lastName)
        {
            EmailId = emailId;
            FirstName = firstName;
            LastName = lastName;
        }
    }
}
