// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ons.Outputs
{

    [OutputType]
    public sealed class GetSubscriptionsSubscriptionResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The time when this suscription was created.
        /// </summary>
        public readonly string CreatedTime;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        public readonly ImmutableArray<Outputs.GetSubscriptionsSubscriptionDeliveryPolicyResult> DeliveryPolicies;
        /// <summary>
        /// A locator that corresponds to the subscription protocol.  For example, an email address for a subscription that uses the `EMAIL` protocol, or a URL for a subscription that uses an HTTP-based protocol. Avoid entering confidential information.
        /// </summary>
        public readonly string Endpoint;
        /// <summary>
        /// For optimistic concurrency control. See `if-match`.
        /// </summary>
        public readonly string Etag;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The protocol used for the subscription.
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// The lifecycle state of the subscription. The status of a new subscription is PENDING; when confirmed, the subscription status changes to ACTIVE.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Return all subscriptions that are subscribed to the given topic OCID. Either this query parameter or the compartmentId query parameter must be set.
        /// </summary>
        public readonly string TopicId;

        [OutputConstructor]
        private GetSubscriptionsSubscriptionResult(
            string compartmentId,

            string createdTime,

            ImmutableDictionary<string, string> definedTags,

            ImmutableArray<Outputs.GetSubscriptionsSubscriptionDeliveryPolicyResult> deliveryPolicies,

            string endpoint,

            string etag,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string protocol,

            string state,

            string topicId)
        {
            CompartmentId = compartmentId;
            CreatedTime = createdTime;
            DefinedTags = definedTags;
            DeliveryPolicies = deliveryPolicies;
            Endpoint = endpoint;
            Etag = etag;
            FreeformTags = freeformTags;
            Id = id;
            Protocol = protocol;
            State = state;
            TopicId = topicId;
        }
    }
}
