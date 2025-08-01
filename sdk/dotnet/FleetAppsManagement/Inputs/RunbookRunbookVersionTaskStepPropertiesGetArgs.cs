// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class RunbookRunbookVersionTaskStepPropertiesGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The action to be taken in case of a failure.
        /// </summary>
        [Input("actionOnFailure", required: true)]
        public Input<string> ActionOnFailure { get; set; } = null!;

        /// <summary>
        /// Preferences to send notifications on the task activities.
        /// </summary>
        [Input("notificationPreferences")]
        public Input<Inputs.RunbookRunbookVersionTaskStepPropertiesNotificationPreferencesGetArgs>? NotificationPreferences { get; set; }

        /// <summary>
        /// Pause Details
        /// </summary>
        [Input("pauseDetails")]
        public Input<Inputs.RunbookRunbookVersionTaskStepPropertiesPauseDetailsGetArgs>? PauseDetails { get; set; }

        /// <summary>
        /// Build control flow conditions that determine the relevance of the task execution.
        /// </summary>
        [Input("preCondition")]
        public Input<string>? PreCondition { get; set; }

        /// <summary>
        /// The runon conditions
        /// </summary>
        [Input("runOn")]
        public Input<Inputs.RunbookRunbookVersionTaskStepPropertiesRunOnGetArgs>? RunOn { get; set; }

        public RunbookRunbookVersionTaskStepPropertiesGetArgs()
        {
        }
        public static new RunbookRunbookVersionTaskStepPropertiesGetArgs Empty => new RunbookRunbookVersionTaskStepPropertiesGetArgs();
    }
}
