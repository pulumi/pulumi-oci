// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class RunbookVersionGroupPropertiesNotificationPreferencesGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Enables notification on pause.
        /// </summary>
        [Input("shouldNotifyOnPause")]
        public Input<bool>? ShouldNotifyOnPause { get; set; }

        /// <summary>
        /// (Updatable) Enables or disables notification on Task
        /// Failures.
        /// </summary>
        [Input("shouldNotifyOnTaskFailure")]
        public Input<bool>? ShouldNotifyOnTaskFailure { get; set; }

        /// <summary>
        /// (Updatable) Enables or disables notification on Task Success.
        /// </summary>
        [Input("shouldNotifyOnTaskSuccess")]
        public Input<bool>? ShouldNotifyOnTaskSuccess { get; set; }

        public RunbookVersionGroupPropertiesNotificationPreferencesGetArgs()
        {
        }
        public static new RunbookVersionGroupPropertiesNotificationPreferencesGetArgs Empty => new RunbookVersionGroupPropertiesNotificationPreferencesGetArgs();
    }
}
