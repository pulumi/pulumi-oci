// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage.Outputs
{

    [OutputType]
    public sealed class GetFilesystemSnapshotPolicyScheduleResult
    {
        /// <summary>
        /// The day of the month to create a scheduled snapshot. If the day does not exist for the month, snapshot creation will be skipped. Used for MONTHLY and YEARLY snapshot schedules.
        /// </summary>
        public readonly int DayOfMonth;
        /// <summary>
        /// The day of the week to create a scheduled snapshot. Used for WEEKLY snapshot schedules.
        /// </summary>
        public readonly string DayOfWeek;
        /// <summary>
        /// The hour of the day to create a DAILY, WEEKLY, MONTHLY, or YEARLY snapshot. If not set, a value will be chosen at creation time.
        /// </summary>
        public readonly int HourOfDay;
        /// <summary>
        /// The month to create a scheduled snapshot. Used only for YEARLY snapshot schedules.
        /// </summary>
        public readonly string Month;
        /// <summary>
        /// The frequency of scheduled snapshots.
        /// </summary>
        public readonly string Period;
        /// <summary>
        /// The number of seconds to retain snapshots created with this schedule. Snapshot expiration time will not be set if this value is empty.
        /// </summary>
        public readonly string RetentionDurationInSeconds;
        /// <summary>
        /// A name prefix to be applied to snapshots created by this schedule.  Example: `compliance1`
        /// </summary>
        public readonly string SchedulePrefix;
        /// <summary>
        /// The starting point used to begin the scheduling of the snapshots based upon recurrence string in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. If no `timeScheduleStart` is provided, the value will be set to the time when the schedule was created.
        /// </summary>
        public readonly string TimeScheduleStart;
        /// <summary>
        /// Time zone used for scheduling the snapshot.
        /// </summary>
        public readonly string TimeZone;

        [OutputConstructor]
        private GetFilesystemSnapshotPolicyScheduleResult(
            int dayOfMonth,

            string dayOfWeek,

            int hourOfDay,

            string month,

            string period,

            string retentionDurationInSeconds,

            string schedulePrefix,

            string timeScheduleStart,

            string timeZone)
        {
            DayOfMonth = dayOfMonth;
            DayOfWeek = dayOfWeek;
            HourOfDay = hourOfDay;
            Month = month;
            Period = period;
            RetentionDurationInSeconds = retentionDurationInSeconds;
            SchedulePrefix = schedulePrefix;
            TimeScheduleStart = timeScheduleStart;
            TimeZone = timeZone;
        }
    }
}