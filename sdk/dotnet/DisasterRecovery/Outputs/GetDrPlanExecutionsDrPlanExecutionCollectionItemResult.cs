// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Outputs
{

    [OutputType]
    public sealed class GetDrPlanExecutionsDrPlanExecutionCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment containing this DR Plan Execution.  Example: `ocid1.compartment.oc1..exampleocid1`
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
        /// </summary>
        public readonly string DrProtectionGroupId;
        /// <summary>
        /// The total duration in seconds taken to complete step execution.  Example: `35`
        /// </summary>
        public readonly int ExecutionDurationInSec;
        /// <summary>
        /// The options for a plan execution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOptionResult> ExecutionOptions;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// A list of groups executed in this DR Plan Execution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecutionResult> GroupExecutions;
        /// <summary>
        /// The OCID of the DR Plan Execution.  Example: `ocid1.drplanexecution.oc1.iad.exampleocid2`
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the DR Plan Execution's current state in more detail.  Example: `The DR Plan Execution [Execution - EBS Switchover PHX to IAD] is currently in progress`
        /// </summary>
        public readonly string LifeCycleDetails;
        /// <summary>
        /// Information about an Object Storage log location for a DR Protection Group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocationResult> LogLocations;
        /// <summary>
        /// The OCID of peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
        /// </summary>
        public readonly string PeerDrProtectionGroupId;
        /// <summary>
        /// The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
        /// </summary>
        public readonly string PeerRegion;
        /// <summary>
        /// The type of the DR Plan executed.
        /// </summary>
        public readonly string PlanExecutionType;
        /// <summary>
        /// The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid2`
        /// </summary>
        public readonly string PlanId;
        /// <summary>
        /// A filter to return only DR Plan Executions that match the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time at which DR Plan Execution was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The time at which DR Plan Execution was last updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDrPlanExecutionsDrPlanExecutionCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string drProtectionGroupId,

            int executionDurationInSec,

            ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOptionResult> executionOptions,

            ImmutableDictionary<string, object> freeformTags,

            ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecutionResult> groupExecutions,

            string id,

            string lifeCycleDetails,

            ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocationResult> logLocations,

            string peerDrProtectionGroupId,

            string peerRegion,

            string planExecutionType,

            string planId,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeEnded,

            string timeStarted,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DrProtectionGroupId = drProtectionGroupId;
            ExecutionDurationInSec = executionDurationInSec;
            ExecutionOptions = executionOptions;
            FreeformTags = freeformTags;
            GroupExecutions = groupExecutions;
            Id = id;
            LifeCycleDetails = lifeCycleDetails;
            LogLocations = logLocations;
            PeerDrProtectionGroupId = peerDrProtectionGroupId;
            PeerRegion = peerRegion;
            PlanExecutionType = planExecutionType;
            PlanId = planId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            TimeUpdated = timeUpdated;
        }
    }
}