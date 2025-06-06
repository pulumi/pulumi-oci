// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetScheduledActionsScheduledActionCollectionItemResult
    {
        /// <summary>
        /// The list of action members in a scheduled action.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetScheduledActionsScheduledActionCollectionItemActionMemberResult> ActionMembers;
        /// <summary>
        /// The order of the scheduled action.
        /// </summary>
        public readonly int ActionOrder;
        /// <summary>
        /// Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> ActionParams;
        /// <summary>
        /// The type of the scheduled action being performed
        /// </summary>
        public readonly string ActionType;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The estimated patching time for the scheduled action.
        /// </summary>
        public readonly int EstimatedTimeInMins;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A filter to return only resources that match the given Scheduled Action id exactly.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A filter to return only resources that match the given scheduling policy id exactly.
        /// </summary>
        public readonly string SchedulingPlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
        /// </summary>
        public readonly string SchedulingWindowId;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the Scheduled Action Resource was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the Scheduled Action Resource was updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetScheduledActionsScheduledActionCollectionItemResult(
            ImmutableArray<Outputs.GetScheduledActionsScheduledActionCollectionItemActionMemberResult> actionMembers,

            int actionOrder,

            ImmutableDictionary<string, string> actionParams,

            string actionType,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            int estimatedTimeInMins,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string schedulingPlanId,

            string schedulingWindowId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            ActionMembers = actionMembers;
            ActionOrder = actionOrder;
            ActionParams = actionParams;
            ActionType = actionType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            EstimatedTimeInMins = estimatedTimeInMins;
            FreeformTags = freeformTags;
            Id = id;
            SchedulingPlanId = schedulingPlanId;
            SchedulingWindowId = schedulingWindowId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
