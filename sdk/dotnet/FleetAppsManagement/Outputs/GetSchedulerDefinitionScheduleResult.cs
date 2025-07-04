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
    public sealed class GetSchedulerDefinitionScheduleResult
    {
        /// <summary>
        /// Duration of the schedule.
        /// </summary>
        public readonly string Duration;
        /// <summary>
        /// Start Date for the schedule. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string ExecutionStartdate;
        /// <summary>
        /// Provide MaintenanceWindowId
        /// </summary>
        public readonly string MaintenanceWindowId;
        /// <summary>
        /// Recurrence rule specification if recurring
        /// </summary>
        public readonly string Recurrences;
        /// <summary>
        /// Schedule Type
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetSchedulerDefinitionScheduleResult(
            string duration,

            string executionStartdate,

            string maintenanceWindowId,

            string recurrences,

            string type)
        {
            Duration = duration;
            ExecutionStartdate = executionStartdate;
            MaintenanceWindowId = maintenanceWindowId;
            Recurrences = recurrences;
            Type = type;
        }
    }
}
