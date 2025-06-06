// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class KeyAutoKeyRotationDetails
    {
        /// <summary>
        /// (Updatable) The last execution status message of auto key rotation.
        /// </summary>
        public readonly string? LastRotationMessage;
        /// <summary>
        /// (Updatable) The status of last execution of auto key rotation.
        /// </summary>
        public readonly string? LastRotationStatus;
        /// <summary>
        /// (Updatable) The interval of auto key rotation. For auto key rotation the interval should between 60 day and 365 days (1 year). Note: User must specify this parameter when creating a new schedule.
        /// </summary>
        public readonly int? RotationIntervalInDays;
        /// <summary>
        /// (Updatable) A property indicating Last rotation Date. Example: `2023-04-04T00:00:00Z`.
        /// </summary>
        public readonly string? TimeOfLastRotation;
        /// <summary>
        /// (Updatable) A property indicating Next estimated scheduled Time, as per the interval, expressed as date YYYY-MM-DD String. Example: `2023-04-04T00:00:00Z`. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z.
        /// </summary>
        public readonly string? TimeOfNextRotation;
        /// <summary>
        /// (Updatable) A property indicating  scheduled start date expressed as date YYYY-MM-DD String. Example: `2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z . Note : Today’s date will be used if not specified by customer.
        /// </summary>
        public readonly string? TimeOfScheduleStart;

        [OutputConstructor]
        private KeyAutoKeyRotationDetails(
            string? lastRotationMessage,

            string? lastRotationStatus,

            int? rotationIntervalInDays,

            string? timeOfLastRotation,

            string? timeOfNextRotation,

            string? timeOfScheduleStart)
        {
            LastRotationMessage = lastRotationMessage;
            LastRotationStatus = lastRotationStatus;
            RotationIntervalInDays = rotationIntervalInDays;
            TimeOfLastRotation = timeOfLastRotation;
            TimeOfNextRotation = timeOfNextRotation;
            TimeOfScheduleStart = timeOfScheduleStart;
        }
    }
}
