// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetDeploymentUpgradesDeploymentUpgradeCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Tags defined for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
        /// </summary>
        public readonly string DeploymentId;
        /// <summary>
        /// The type of the deployment upgrade: MANUAL or AUTOMATIC
        /// </summary>
        public readonly string DeploymentUpgradeType;
        /// <summary>
        /// Metadata about this specific object.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only.  Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment upgrade being referenced.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates if cancel is allowed. Scheduled upgrade can be cancelled only if target version is not forced by service,  otherwise only reschedule allowed.
        /// </summary>
        public readonly bool IsCancelAllowed;
        /// <summary>
        /// Indicates if reschedule is allowed. Upgrade can be rescheduled postponed until the end of the service defined auto-upgrade period.
        /// </summary>
        public readonly bool IsRescheduleAllowed;
        /// <summary>
        /// Indicates if rollback is allowed. In practice only the last upgrade can be rolled back.
        /// * Manual upgrade is allowed to rollback only until the old version isn't deprecated yet.
        /// * Automatic upgrade by default is not allowed, unless a serious issue does not justify.
        /// </summary>
        public readonly bool IsRollbackAllowed;
        /// <summary>
        /// Indicates if OGG release contains security fix.
        /// </summary>
        public readonly bool IsSecurityFix;
        /// <summary>
        /// Indicates if upgrade notifications are snoozed or not.
        /// </summary>
        public readonly bool IsSnoozed;
        /// <summary>
        /// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Possible GGS lifecycle sub-states.
        /// </summary>
        public readonly string LifecycleSubState;
        /// <summary>
        /// Version of OGG
        /// </summary>
        public readonly string OggVersion;
        /// <summary>
        /// Version of OGG
        /// </summary>
        public readonly string PreviousOggVersion;
        /// <summary>
        /// The type of release.
        /// </summary>
        public readonly string ReleaseType;
        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the request was finished. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The time until OGG version is supported. After this date has passed OGG version will not be available anymore. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeOggVersionSupportedUntil;
        /// <summary>
        /// The time the resource was released. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeReleased;
        /// <summary>
        /// The time of upgrade schedule. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeSchedule;
        /// <summary>
        /// Indicates the latest time until the deployment upgrade could be rescheduled. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeScheduleMax;
        /// <summary>
        /// The time the upgrade notifications are snoozed until. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeSnoozedUntil;
        /// <summary>
        /// The date and time the request was started. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeploymentUpgradesDeploymentUpgradeCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string deploymentId,

            string deploymentUpgradeType,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isCancelAllowed,

            bool isRescheduleAllowed,

            bool isRollbackAllowed,

            bool isSecurityFix,

            bool isSnoozed,

            string lifecycleDetails,

            string lifecycleSubState,

            string oggVersion,

            string previousOggVersion,

            string releaseType,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeFinished,

            string timeOggVersionSupportedUntil,

            string timeReleased,

            string timeSchedule,

            string timeScheduleMax,

            string timeSnoozedUntil,

            string timeStarted,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeploymentId = deploymentId;
            DeploymentUpgradeType = deploymentUpgradeType;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsCancelAllowed = isCancelAllowed;
            IsRescheduleAllowed = isRescheduleAllowed;
            IsRollbackAllowed = isRollbackAllowed;
            IsSecurityFix = isSecurityFix;
            IsSnoozed = isSnoozed;
            LifecycleDetails = lifecycleDetails;
            LifecycleSubState = lifecycleSubState;
            OggVersion = oggVersion;
            PreviousOggVersion = previousOggVersion;
            ReleaseType = releaseType;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeFinished = timeFinished;
            TimeOggVersionSupportedUntil = timeOggVersionSupportedUntil;
            TimeReleased = timeReleased;
            TimeSchedule = timeSchedule;
            TimeScheduleMax = timeScheduleMax;
            TimeSnoozedUntil = timeSnoozedUntil;
            TimeStarted = timeStarted;
            TimeUpdated = timeUpdated;
        }
    }
}
