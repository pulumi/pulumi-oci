// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AnnouncementsService
{
    public static class GetAnnouncementSubscription
    {
        /// <summary>
        /// This data source provides details about a specific Announcement Subscription resource in Oracle Cloud Infrastructure Announcements Service service.
        /// 
        /// Gets the specified announcement subscription.
        /// 
        /// This call is subject to an Announcements limit that applies to the total number of requests across all read or write operations. Announcements might throttle this call to reject an otherwise valid request when the total rate of operations exceeds 20 requests per second for a given user. The service might also throttle this call to reject an otherwise valid request when the total rate of operations exceeds 100 requests per second for a given tenancy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAnnouncementSubscription = Oci.AnnouncementsService.GetAnnouncementSubscription.Invoke(new()
        ///     {
        ///         AnnouncementSubscriptionId = testAnnouncementSubscriptionOciAnnouncementsServiceAnnouncementSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAnnouncementSubscriptionResult> InvokeAsync(GetAnnouncementSubscriptionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAnnouncementSubscriptionResult>("oci:AnnouncementsService/getAnnouncementSubscription:getAnnouncementSubscription", args ?? new GetAnnouncementSubscriptionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Announcement Subscription resource in Oracle Cloud Infrastructure Announcements Service service.
        /// 
        /// Gets the specified announcement subscription.
        /// 
        /// This call is subject to an Announcements limit that applies to the total number of requests across all read or write operations. Announcements might throttle this call to reject an otherwise valid request when the total rate of operations exceeds 20 requests per second for a given user. The service might also throttle this call to reject an otherwise valid request when the total rate of operations exceeds 100 requests per second for a given tenancy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAnnouncementSubscription = Oci.AnnouncementsService.GetAnnouncementSubscription.Invoke(new()
        ///     {
        ///         AnnouncementSubscriptionId = testAnnouncementSubscriptionOciAnnouncementsServiceAnnouncementSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAnnouncementSubscriptionResult> Invoke(GetAnnouncementSubscriptionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAnnouncementSubscriptionResult>("oci:AnnouncementsService/getAnnouncementSubscription:getAnnouncementSubscription", args ?? new GetAnnouncementSubscriptionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Announcement Subscription resource in Oracle Cloud Infrastructure Announcements Service service.
        /// 
        /// Gets the specified announcement subscription.
        /// 
        /// This call is subject to an Announcements limit that applies to the total number of requests across all read or write operations. Announcements might throttle this call to reject an otherwise valid request when the total rate of operations exceeds 20 requests per second for a given user. The service might also throttle this call to reject an otherwise valid request when the total rate of operations exceeds 100 requests per second for a given tenancy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAnnouncementSubscription = Oci.AnnouncementsService.GetAnnouncementSubscription.Invoke(new()
        ///     {
        ///         AnnouncementSubscriptionId = testAnnouncementSubscriptionOciAnnouncementsServiceAnnouncementSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAnnouncementSubscriptionResult> Invoke(GetAnnouncementSubscriptionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAnnouncementSubscriptionResult>("oci:AnnouncementsService/getAnnouncementSubscription:getAnnouncementSubscription", args ?? new GetAnnouncementSubscriptionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAnnouncementSubscriptionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the announcement subscription.
        /// </summary>
        [Input("announcementSubscriptionId", required: true)]
        public string AnnouncementSubscriptionId { get; set; } = null!;

        public GetAnnouncementSubscriptionArgs()
        {
        }
        public static new GetAnnouncementSubscriptionArgs Empty => new GetAnnouncementSubscriptionArgs();
    }

    public sealed class GetAnnouncementSubscriptionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the announcement subscription.
        /// </summary>
        [Input("announcementSubscriptionId", required: true)]
        public Input<string> AnnouncementSubscriptionId { get; set; } = null!;

        public GetAnnouncementSubscriptionInvokeArgs()
        {
        }
        public static new GetAnnouncementSubscriptionInvokeArgs Empty => new GetAnnouncementSubscriptionInvokeArgs();
    }


    [OutputType]
    public sealed class GetAnnouncementSubscriptionResult
    {
        public readonly string AnnouncementSubscriptionId;
        /// <summary>
        /// The OCID of the compartment that contains the announcement subscription.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A description of the announcement subscription. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name for the announcement subscription. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A list of filter groups for the announcement subscription. A filter group is a combination of multiple filters applied to announcements for matching purposes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAnnouncementSubscriptionFilterGroupResult> FilterGroups;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the announcement subscription.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current lifecycle state in more detail. For example, details might provide required or recommended actions for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription.
        /// </summary>
        public readonly string OnsTopicId;
        /// <summary>
        /// (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
        /// </summary>
        public readonly string PreferredLanguage;
        /// <summary>
        /// The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
        /// </summary>
        public readonly string PreferredTimeZone;
        /// <summary>
        /// The current lifecycle state of the announcement subscription.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time that the announcement subscription was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time that the announcement subscription was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetAnnouncementSubscriptionResult(
            string announcementSubscriptionId,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableArray<Outputs.GetAnnouncementSubscriptionFilterGroupResult> filterGroups,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string onsTopicId,

            string preferredLanguage,

            string preferredTimeZone,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AnnouncementSubscriptionId = announcementSubscriptionId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FilterGroups = filterGroups;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            OnsTopicId = onsTopicId;
            PreferredLanguage = preferredLanguage;
            PreferredTimeZone = preferredTimeZone;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
