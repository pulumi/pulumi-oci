// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemResult
    {
        /// <summary>
        /// Contains the approver details who have approved the privilegedApi Request during the initial request.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemApproverDetailResult> ApproverDetails;
        /// <summary>
        /// The comment entered by the operator while closing the request.
        /// </summary>
        public readonly string ClosureComment;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Duration in hours for which access is sought on the target resource.
        /// </summary>
        public readonly int DurationInHrs;
        /// <summary>
        /// entityType of resource for which the AccessRequest is applicable
        /// </summary>
        public readonly string EntityType;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiRequest.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// more in detail about the lifeCycleState.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the Oracle Cloud Infrastructure Notification topic to publish messages related to this privileged api request.
        /// </summary>
        public readonly string NotificationTopicId;
        /// <summary>
        /// Number of approvers required to approve an privilegedApi request.
        /// </summary>
        public readonly int NumberOfApproversRequired;
        /// <summary>
        /// The OCID of the privilegedApi control governing the target resource.
        /// </summary>
        public readonly string PrivilegedApiControlId;
        /// <summary>
        /// Name of the privilegedApi control governing the target resource.
        /// </summary>
        public readonly string PrivilegedApiControlName;
        /// <summary>
        /// List of api names, attributes for which approval is sought by the user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemPrivilegedOperationListResult> PrivilegedOperationLists;
        /// <summary>
        /// Reason in Detail for which the operator is requesting access on the target resource.
        /// </summary>
        public readonly string ReasonDetail;
        /// <summary>
        /// Summary comment by the operator creating the access request.
        /// </summary>
        public readonly string ReasonSummary;
        /// <summary>
        /// This is an automatic identifier generated by the system which is easier for human comprehension.
        /// </summary>
        public readonly string RequestId;
        /// <summary>
        /// List of Users who has created this privilegedApiRequest.
        /// </summary>
        public readonly ImmutableArray<string> RequestedBies;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource .
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// resourceName for which the PrivilegedApiRequest is applicable
        /// </summary>
        public readonly string ResourceName;
        /// <summary>
        /// A filter to return only lists of resources that match the entire given service type.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// Priority assigned to the access request by the operator
        /// </summary>
        public readonly string Severity;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A message that describes the current state of the PrivilegedApiControl in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string StateDetails;
        /// <summary>
        /// The subresource names requested for approval.
        /// </summary>
        public readonly ImmutableArray<string> SubResourceNameLists;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// A list of ticket numbers related to this Privileged Api Access Request, e.g. Service Request (SR) number and JIRA ticket number.
        /// </summary>
        public readonly ImmutableArray<string> TicketNumbers;
        /// <summary>
        /// Time when the privilegedApi request was created in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format. Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time in future when the user for the privilegedApi request needs to be created in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format. Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeRequestedForFutureAccess;
        /// <summary>
        /// Time when the privilegedApi request was last modified in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format. Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemResult(
            ImmutableArray<Outputs.GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemApproverDetailResult> approverDetails,

            string closureComment,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            int durationInHrs,

            string entityType,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string notificationTopicId,

            int numberOfApproversRequired,

            string privilegedApiControlId,

            string privilegedApiControlName,

            ImmutableArray<Outputs.GetApiaccesscontrolPrivilegedApiRequestsPrivilegedApiRequestCollectionItemPrivilegedOperationListResult> privilegedOperationLists,

            string reasonDetail,

            string reasonSummary,

            string requestId,

            ImmutableArray<string> requestedBies,

            string resourceId,

            string resourceName,

            string resourceType,

            string severity,

            string state,

            string stateDetails,

            ImmutableArray<string> subResourceNameLists,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<string> ticketNumbers,

            string timeCreated,

            string timeRequestedForFutureAccess,

            string timeUpdated)
        {
            ApproverDetails = approverDetails;
            ClosureComment = closureComment;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DurationInHrs = durationInHrs;
            EntityType = entityType;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NotificationTopicId = notificationTopicId;
            NumberOfApproversRequired = numberOfApproversRequired;
            PrivilegedApiControlId = privilegedApiControlId;
            PrivilegedApiControlName = privilegedApiControlName;
            PrivilegedOperationLists = privilegedOperationLists;
            ReasonDetail = reasonDetail;
            ReasonSummary = reasonSummary;
            RequestId = requestId;
            RequestedBies = requestedBies;
            ResourceId = resourceId;
            ResourceName = resourceName;
            ResourceType = resourceType;
            Severity = severity;
            State = state;
            StateDetails = stateDetails;
            SubResourceNameLists = subResourceNameLists;
            SystemTags = systemTags;
            TicketNumbers = ticketNumbers;
            TimeCreated = timeCreated;
            TimeRequestedForFutureAccess = timeRequestedForFutureAccess;
            TimeUpdated = timeUpdated;
        }
    }
}
