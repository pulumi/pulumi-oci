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
    public sealed class RunbookVersionGroupProperties
    {
        /// <summary>
        /// (Updatable) The action to be taken in case of a failure.
        /// </summary>
        public readonly string ActionOnFailure;
        /// <summary>
        /// (Updatable) Preferences to send notifications on the task activities.
        /// </summary>
        public readonly Outputs.RunbookVersionGroupPropertiesNotificationPreferences? NotificationPreferences;
        /// <summary>
        /// (Updatable) Pause Details
        /// </summary>
        public readonly Outputs.RunbookVersionGroupPropertiesPauseDetails? PauseDetails;
        /// <summary>
        /// (Updatable) Build control flow conditions that determine the relevance of the
        /// task execution.
        /// </summary>
        public readonly string? PreCondition;
        /// <summary>
        /// (Updatable) The runon conditions
        /// </summary>
        public readonly Outputs.RunbookVersionGroupPropertiesRunOn? RunOn;

        [OutputConstructor]
        private RunbookVersionGroupProperties(
            string actionOnFailure,

            Outputs.RunbookVersionGroupPropertiesNotificationPreferences? notificationPreferences,

            Outputs.RunbookVersionGroupPropertiesPauseDetails? pauseDetails,

            string? preCondition,

            Outputs.RunbookVersionGroupPropertiesRunOn? runOn)
        {
            ActionOnFailure = actionOnFailure;
            NotificationPreferences = notificationPreferences;
            PauseDetails = pauseDetails;
            PreCondition = preCondition;
            RunOn = runOn;
        }
    }
}
