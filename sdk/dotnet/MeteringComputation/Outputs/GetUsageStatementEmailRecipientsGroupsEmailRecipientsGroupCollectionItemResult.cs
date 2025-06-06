// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Outputs
{

    [OutputType]
    public sealed class GetUsageStatementEmailRecipientsGroupsEmailRecipientsGroupCollectionItemResult
    {
        /// <summary>
        /// The compartment ID in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string EmailRecipientsGroupId;
        /// <summary>
        /// The usage statement email recipients group OCID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of recipients that will receive usage statement emails.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetUsageStatementEmailRecipientsGroupsEmailRecipientsGroupCollectionItemRecipientsListResult> RecipientsLists;
        /// <summary>
        /// The email recipients group lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The usage statement subscription unique OCID.
        /// </summary>
        public readonly string SubscriptionId;

        [OutputConstructor]
        private GetUsageStatementEmailRecipientsGroupsEmailRecipientsGroupCollectionItemResult(
            string compartmentId,

            string emailRecipientsGroupId,

            string id,

            ImmutableArray<Outputs.GetUsageStatementEmailRecipientsGroupsEmailRecipientsGroupCollectionItemRecipientsListResult> recipientsLists,

            string state,

            string subscriptionId)
        {
            CompartmentId = compartmentId;
            EmailRecipientsGroupId = emailRecipientsGroupId;
            Id = id;
            RecipientsLists = recipientsLists;
            State = state;
            SubscriptionId = subscriptionId;
        }
    }
}
