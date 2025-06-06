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
    public sealed class GetDatabaseMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionResult
    {
        /// <summary>
        /// List of action members of this execution action.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMemberResult> ActionMembers;
        /// <summary>
        /// Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> ActionParams;
        /// <summary>
        /// The action type of the execution action being performed
        /// </summary>
        public readonly string ActionType;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description of the maintenance run.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The user-friendly name for the maintenance run.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The estimated time of the execution window in minutes.
        /// </summary>
        public readonly int EstimatedTimeInMins;
        /// <summary>
        /// The priority order of the execution action.
        /// </summary>
        public readonly int ExecutionActionOrder;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
        /// </summary>
        public readonly string ExecutionWindowId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the maintenance run.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
        /// </summary>
        public readonly string LifecycleSubstate;
        /// <summary>
        /// The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the execution window was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last date and time that the execution window was updated.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The total time taken by corresponding resource activity in minutes.
        /// </summary>
        public readonly int TotalTimeTakenInMins;

        [OutputConstructor]
        private GetDatabaseMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionResult(
            ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMemberResult> actionMembers,

            ImmutableDictionary<string, string> actionParams,

            string actionType,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            int estimatedTimeInMins,

            int executionActionOrder,

            string executionWindowId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string lifecycleSubstate,

            string state,

            string timeCreated,

            string timeUpdated,

            int totalTimeTakenInMins)
        {
            ActionMembers = actionMembers;
            ActionParams = actionParams;
            ActionType = actionType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            EstimatedTimeInMins = estimatedTimeInMins;
            ExecutionActionOrder = executionActionOrder;
            ExecutionWindowId = executionWindowId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            LifecycleSubstate = lifecycleSubstate;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TotalTimeTakenInMins = totalTimeTakenInMins;
        }
    }
}
