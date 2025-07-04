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
    public sealed class GetFleetNotificationPreferenceResult
    {
        /// <summary>
        /// Compartment Identifier[OCID].
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Preferences to send notifications on the fleet activities.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetNotificationPreferencePreferenceResult> Preferences;
        /// <summary>
        /// Topic Id where the notifications will be directed. A topic is a communication channel for sending messages on chosen events to subscriptions.
        /// </summary>
        public readonly string TopicId;

        [OutputConstructor]
        private GetFleetNotificationPreferenceResult(
            string compartmentId,

            ImmutableArray<Outputs.GetFleetNotificationPreferencePreferenceResult> preferences,

            string topicId)
        {
            CompartmentId = compartmentId;
            Preferences = preferences;
            TopicId = topicId;
        }
    }
}
