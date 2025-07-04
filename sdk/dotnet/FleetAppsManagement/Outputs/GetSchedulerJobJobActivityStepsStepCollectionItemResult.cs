// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetSchedulerJobJobActivityStepsStepCollectionItemResult
    {
        /// <summary>
        /// Description of the step Execution.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Is this a rollback task?
        /// </summary>
        public readonly bool IsRollbackTask;
        /// <summary>
        /// Task Order Sequence
        /// </summary>
        public readonly string Sequence;
        /// <summary>
        /// Status of the Task.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Unique step name
        /// </summary>
        public readonly string StepName;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The OCID of taskRecord assocaited with the step.
        /// </summary>
        public readonly string TaskRecordId;
        /// <summary>
        /// The time the task ended. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// The time the task started. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeStarted;

        [OutputConstructor]
        private GetSchedulerJobJobActivityStepsStepCollectionItemResult(
            string description,

            bool isRollbackTask,

            string sequence,

            string status,

            string stepName,

            ImmutableDictionary<string, string> systemTags,

            string taskRecordId,

            string timeEnded,

            string timeStarted)
        {
            Description = description;
            IsRollbackTask = isRollbackTask;
            Sequence = sequence;
            Status = status;
            StepName = stepName;
            SystemTags = systemTags;
            TaskRecordId = taskRecordId;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
        }
    }
}
