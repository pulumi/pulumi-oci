// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Monitoring.Outputs
{

    [OutputType]
    public sealed class GetAlarmHistoryCollectionEntryResult
    {
        /// <summary>
        /// Description for this alarm history entry.
        /// </summary>
        public readonly string Summary;
        /// <summary>
        /// Timestamp for this alarm history entry. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
        /// </summary>
        public readonly string Timestamp;
        /// <summary>
        /// Timestamp for the transition of the alarm state. For example, the time when the alarm transitioned from OK to Firing. Available for state transition entries only. Note: A three-minute lag for this value accounts for any late-arriving metrics.  Example: `2019-02-01T0:59:00.789Z`
        /// </summary>
        public readonly string TimestampTriggered;

        [OutputConstructor]
        private GetAlarmHistoryCollectionEntryResult(
            string summary,

            string timestamp,

            string timestampTriggered)
        {
            Summary = summary;
            Timestamp = timestamp;
            TimestampTriggered = timestampTriggered;
        }
    }
}
