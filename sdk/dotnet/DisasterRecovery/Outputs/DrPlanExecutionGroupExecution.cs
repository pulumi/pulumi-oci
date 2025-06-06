// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Outputs
{

    [OutputType]
    public sealed class DrPlanExecutionGroupExecution
    {
        /// <summary>
        /// (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The total duration in seconds taken to complete the step execution.  Example: `35`
        /// </summary>
        public readonly int? ExecutionDurationInSec;
        /// <summary>
        /// The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..uniqueID`
        /// </summary>
        public readonly string? GroupId;
        /// <summary>
        /// The status of the step execution.
        /// </summary>
        public readonly string? Status;
        /// <summary>
        /// Additional details on the step execution status.  Example: `This step failed to complete due to a timeout`
        /// </summary>
        public readonly string? StatusDetails;
        /// <summary>
        /// A list of step executions in the group.
        /// </summary>
        public readonly ImmutableArray<Outputs.DrPlanExecutionGroupExecutionStepExecution> StepExecutions;
        /// <summary>
        /// The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string? TimeEnded;
        /// <summary>
        /// The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string? TimeStarted;
        /// <summary>
        /// The group type.  Example: `BUILT_IN`
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private DrPlanExecutionGroupExecution(
            string? displayName,

            int? executionDurationInSec,

            string? groupId,

            string? status,

            string? statusDetails,

            ImmutableArray<Outputs.DrPlanExecutionGroupExecutionStepExecution> stepExecutions,

            string? timeEnded,

            string? timeStarted,

            string? type)
        {
            DisplayName = displayName;
            ExecutionDurationInSec = executionDurationInSec;
            GroupId = groupId;
            Status = status;
            StatusDetails = statusDetails;
            StepExecutions = stepExecutions;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            Type = type;
        }
    }
}
