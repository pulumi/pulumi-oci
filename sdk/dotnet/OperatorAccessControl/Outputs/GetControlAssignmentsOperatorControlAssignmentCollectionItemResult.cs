// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OperatorAccessControl.Outputs
{

    [OutputType]
    public sealed class GetControlAssignmentsOperatorControlAssignmentCollectionItemResult
    {
        /// <summary>
        /// The OCID of the user who created this operator control assignment.
        /// </summary>
        public readonly string AssignerId;
        /// <summary>
        /// Comment about the assignment of the operator control to this target resource.
        /// </summary>
        public readonly string Comment;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace.
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// description containing reason for releasing of OperatorControl.
        /// </summary>
        public readonly string DetachmentDescription;
        /// <summary>
        /// The code identifying the error occurred during Assignment operation.
        /// </summary>
        public readonly int ErrorCode;
        /// <summary>
        /// The message describing the error occurred during Assignment operation.
        /// </summary>
        public readonly string ErrorMessage;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the operator control assignment.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The boolean if true would autoApprove during maintenance.
        /// </summary>
        public readonly bool IsAutoApproveDuringMaintenance;
        /// <summary>
        /// Whether the assignment is a default assignment.
        /// </summary>
        public readonly bool IsDefaultAssignment;
        /// <summary>
        /// If set, then the target resource is always governed by the operator control.
        /// </summary>
        public readonly bool IsEnforcedAlways;
        /// <summary>
        /// If set, then the hypervisor audit logs will be forwarded to the relevant remote syslog server
        /// </summary>
        public readonly bool IsHypervisorLogForwarded;
        /// <summary>
        /// If set indicates that the audit logs are being forwarded to the relevant remote logging server
        /// </summary>
        public readonly bool IsLogForwarded;
        /// <summary>
        /// More in detail about the lifeCycleState.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Name of the operator control name associated.
        /// </summary>
        public readonly string OpControlName;
        /// <summary>
        /// The OCID of the operator control.
        /// </summary>
        public readonly string OperatorControlId;
        /// <summary>
        /// The address of the remote syslog server where the audit logs are being forwarded to. Address in host or IP format.
        /// </summary>
        public readonly string RemoteSyslogServerAddress;
        /// <summary>
        /// The CA certificate of the remote syslog server.
        /// </summary>
        public readonly string RemoteSyslogServerCaCert;
        /// <summary>
        /// The listening port of the remote syslog server. The port range is 0 - 65535. Only TCP supported.
        /// </summary>
        public readonly int RemoteSyslogServerPort;
        /// <summary>
        /// The OCID of the compartment that contains the target resource.
        /// </summary>
        public readonly string ResourceCompartmentId;
        /// <summary>
        /// The OCID of the target resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// A filter to return only resources that match the given ResourceName.
        /// </summary>
        public readonly string ResourceName;
        /// <summary>
        /// A filter to return only lists of resources that match the entire given service type.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given OperatorControlAssignment lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time at which the target resource will be brought under the governance of the operator control expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeAssignmentFrom;
        /// <summary>
        /// The time at which the target resource will leave the governance of the operator control expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeAssignmentTo;
        /// <summary>
        /// Time when the operator control assignment is created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeOfAssignment;
        /// <summary>
        /// Time on which the operator control assignment was deleted in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format.Example: '2020-05-22T21:10:29.600Z'
        /// </summary>
        public readonly string TimeOfDeletion;
        /// <summary>
        /// User id who released the operatorControl.
        /// </summary>
        public readonly string UnassignerId;
        public readonly int ValidateAssignmentTrigger;

        [OutputConstructor]
        private GetControlAssignmentsOperatorControlAssignmentCollectionItemResult(
            string assignerId,

            string comment,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string detachmentDescription,

            int errorCode,

            string errorMessage,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAutoApproveDuringMaintenance,

            bool isDefaultAssignment,

            bool isEnforcedAlways,

            bool isHypervisorLogForwarded,

            bool isLogForwarded,

            string lifecycleDetails,

            string opControlName,

            string operatorControlId,

            string remoteSyslogServerAddress,

            string remoteSyslogServerCaCert,

            int remoteSyslogServerPort,

            string resourceCompartmentId,

            string resourceId,

            string resourceName,

            string resourceType,

            string state,

            string timeAssignmentFrom,

            string timeAssignmentTo,

            string timeOfAssignment,

            string timeOfDeletion,

            string unassignerId,

            int validateAssignmentTrigger)
        {
            AssignerId = assignerId;
            Comment = comment;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DetachmentDescription = detachmentDescription;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
            FreeformTags = freeformTags;
            Id = id;
            IsAutoApproveDuringMaintenance = isAutoApproveDuringMaintenance;
            IsDefaultAssignment = isDefaultAssignment;
            IsEnforcedAlways = isEnforcedAlways;
            IsHypervisorLogForwarded = isHypervisorLogForwarded;
            IsLogForwarded = isLogForwarded;
            LifecycleDetails = lifecycleDetails;
            OpControlName = opControlName;
            OperatorControlId = operatorControlId;
            RemoteSyslogServerAddress = remoteSyslogServerAddress;
            RemoteSyslogServerCaCert = remoteSyslogServerCaCert;
            RemoteSyslogServerPort = remoteSyslogServerPort;
            ResourceCompartmentId = resourceCompartmentId;
            ResourceId = resourceId;
            ResourceName = resourceName;
            ResourceType = resourceType;
            State = state;
            TimeAssignmentFrom = timeAssignmentFrom;
            TimeAssignmentTo = timeAssignmentTo;
            TimeOfAssignment = timeOfAssignment;
            TimeOfDeletion = timeOfDeletion;
            UnassignerId = unassignerId;
            ValidateAssignmentTrigger = validateAssignmentTrigger;
        }
    }
}
