// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy.Outputs
{

    [OutputType]
    public sealed class SubscriptionRedeemableUserItem
    {
        /// <summary>
        /// The email ID for a user that can redeem rewards.
        /// </summary>
        public readonly string EmailId;

        [OutputConstructor]
        private SubscriptionRedeemableUserItem(string emailId)
        {
            EmailId = emailId;
        }
    }
}