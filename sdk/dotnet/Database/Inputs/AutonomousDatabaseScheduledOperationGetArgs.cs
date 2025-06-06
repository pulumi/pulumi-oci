// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousDatabaseScheduledOperationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Day of the week.
        /// </summary>
        [Input("dayOfWeek")]
        public Input<Inputs.AutonomousDatabaseScheduledOperationDayOfWeekGetArgs>? DayOfWeek { get; set; }

        /// <summary>
        /// (Updatable) auto start time. value must be of ISO-8601 format "HH:mm"
        /// </summary>
        [Input("scheduledStartTime")]
        public Input<string>? ScheduledStartTime { get; set; }

        /// <summary>
        /// (Updatable) auto stop time. value must be of ISO-8601 format "HH:mm"
        /// </summary>
        [Input("scheduledStopTime")]
        public Input<string>? ScheduledStopTime { get; set; }

        public AutonomousDatabaseScheduledOperationGetArgs()
        {
        }
        public static new AutonomousDatabaseScheduledOperationGetArgs Empty => new AutonomousDatabaseScheduledOperationGetArgs();
    }
}
