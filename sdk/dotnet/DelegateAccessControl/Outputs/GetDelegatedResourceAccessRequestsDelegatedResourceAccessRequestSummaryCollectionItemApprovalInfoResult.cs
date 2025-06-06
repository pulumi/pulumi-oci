// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DelegateAccessControl.Outputs
{

    [OutputType]
    public sealed class GetDelegatedResourceAccessRequestsDelegatedResourceAccessRequestSummaryCollectionItemApprovalInfoResult
    {
        /// <summary>
        /// Indicated whether the request is approved or rejected.
        /// </summary>
        public readonly string ApprovalAction;
        /// <summary>
        /// approval type, initial or extension
        /// </summary>
        public readonly string ApprovalType;
        /// <summary>
        /// Additional message specified by the approver of the request.
        /// </summary>
        public readonly string ApproverAdditionalMessage;
        /// <summary>
        /// Comment specified by the approver of the request.
        /// </summary>
        public readonly string ApproverComment;
        /// <summary>
        /// User ID of the approver.
        /// </summary>
        public readonly string ApproverId;
        /// <summary>
        /// Access start time that is actually approved by the customer in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format, e.g. '2020-05-22T21:10:29.600Z'.
        /// </summary>
        public readonly string TimeApprovedForAccess;

        [OutputConstructor]
        private GetDelegatedResourceAccessRequestsDelegatedResourceAccessRequestSummaryCollectionItemApprovalInfoResult(
            string approvalAction,

            string approvalType,

            string approverAdditionalMessage,

            string approverComment,

            string approverId,

            string timeApprovedForAccess)
        {
            ApprovalAction = approvalAction;
            ApprovalType = approvalType;
            ApproverAdditionalMessage = approverAdditionalMessage;
            ApproverComment = approverComment;
            ApproverId = approverId;
            TimeApprovedForAccess = timeApprovedForAccess;
        }
    }
}
