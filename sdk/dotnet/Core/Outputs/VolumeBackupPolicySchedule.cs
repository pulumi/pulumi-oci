// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class VolumeBackupPolicySchedule
    {
        /// <summary>
        /// (Updatable) The type of volume backup to create.
        /// </summary>
        public readonly string BackupType;
        /// <summary>
        /// (Updatable) The day of the month to schedule the volume backup.
        /// </summary>
        public readonly int? DayOfMonth;
        /// <summary>
        /// (Updatable) The day of the week to schedule the volume backup.
        /// </summary>
        public readonly string? DayOfWeek;
        /// <summary>
        /// (Updatable) The hour of the day to schedule the volume backup.
        /// </summary>
        public readonly int? HourOfDay;
        /// <summary>
        /// (Updatable) The month of the year to schedule the volume backup.
        /// </summary>
        public readonly string? Month;
        /// <summary>
        /// (Updatable) The number of seconds that the volume backup start time should be shifted from the default interval boundaries specified by the period. The volume backup start time is the frequency start time plus the offset.
        /// </summary>
        public readonly int? OffsetSeconds;
        /// <summary>
        /// (Updatable) Indicates how the offset is defined. If value is `STRUCTURED`, then `hourOfDay`, `dayOfWeek`, `dayOfMonth`, and `month` fields are used and `offsetSeconds` will be ignored in requests and users should ignore its value from the responses.
        /// 
        /// `hourOfDay` is applicable for periods `ONE_DAY`, `ONE_WEEK`, `ONE_MONTH` and `ONE_YEAR`.
        /// 
        /// `dayOfWeek` is applicable for period `ONE_WEEK`.
        /// 
        /// `dayOfMonth` is applicable for periods `ONE_MONTH` and `ONE_YEAR`.
        /// 
        /// 'month' is applicable for period 'ONE_YEAR'.
        /// 
        /// They will be ignored in the requests for inapplicable periods.
        /// 
        /// If value is `NUMERIC_SECONDS`, then `offsetSeconds` will be used for both requests and responses and the structured fields will be ignored in the requests and users should ignore their values from the responses.
        /// 
        /// For clients using older versions of Apis and not sending `offsetType` in their requests, the behaviour is just like `NUMERIC_SECONDS`.
        /// </summary>
        public readonly string? OffsetType;
        /// <summary>
        /// (Updatable) The volume backup frequency.
        /// </summary>
        public readonly string Period;
        /// <summary>
        /// (Updatable) How long, in seconds, to keep the volume backups created by this schedule.
        /// </summary>
        public readonly int RetentionSeconds;
        /// <summary>
        /// (Updatable) Specifies what time zone is the schedule in
        /// enum:
        /// - `UTC`
        /// - `REGIONAL_DATA_CENTER_TIME`
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? TimeZone;

        [OutputConstructor]
        private VolumeBackupPolicySchedule(
            string backupType,

            int? dayOfMonth,

            string? dayOfWeek,

            int? hourOfDay,

            string? month,

            int? offsetSeconds,

            string? offsetType,

            string period,

            int retentionSeconds,

            string? timeZone)
        {
            BackupType = backupType;
            DayOfMonth = dayOfMonth;
            DayOfWeek = dayOfWeek;
            HourOfDay = hourOfDay;
            Month = month;
            OffsetSeconds = offsetSeconds;
            OffsetType = offsetType;
            Period = period;
            RetentionSeconds = retentionSeconds;
            TimeZone = timeZone;
        }
    }
}
