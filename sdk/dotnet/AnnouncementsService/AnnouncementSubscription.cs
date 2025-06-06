// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AnnouncementsService
{
    /// <summary>
    /// This resource provides the Announcement Subscription resource in Oracle Cloud Infrastructure Announcements Service service.
    /// 
    /// Creates a new announcement subscription.
    /// 
    /// This call is subject to an Announcements limit that applies to the total number of requests across all read or write operations. Announcements might throttle this call to reject an otherwise valid request when the total rate of operations exceeds 20 requests per second for a given user. The service might also throttle this call to reject an otherwise valid request when the total rate of operations exceeds 100 requests per second for a given tenancy.
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
    ///     var testAnnouncementSubscription = new Oci.AnnouncementsService.AnnouncementSubscription("test_announcement_subscription", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = announcementSubscriptionDisplayName,
    ///         OnsTopicId = testNotificationTopic.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = announcementSubscriptionDescription,
    ///         FilterGroups = new Oci.AnnouncementsService.Inputs.AnnouncementSubscriptionFilterGroupsArgs
    ///         {
    ///             Filters = new[]
    ///             {
    ///                 new Oci.AnnouncementsService.Inputs.AnnouncementSubscriptionFilterGroupsFilterArgs
    ///                 {
    ///                     Type = announcementSubscriptionFilterGroupsFiltersType,
    ///                     Value = announcementSubscriptionFilterGroupsFiltersValue,
    ///                 },
    ///             },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         PreferredLanguage = announcementSubscriptionPreferredLanguage,
    ///         PreferredTimeZone = announcementSubscriptionPreferredTimeZone,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// AnnouncementSubscriptions can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:AnnouncementsService/announcementSubscription:AnnouncementSubscription test_announcement_subscription "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:AnnouncementsService/announcementSubscription:AnnouncementSubscription")]
    public partial class AnnouncementSubscription : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A description of the announcement subscription. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
        /// </summary>
        [Output("filterGroups")]
        public Output<Outputs.AnnouncementSubscriptionFilterGroups> FilterGroups { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current lifecycle state in more detail. For example, details might provide required or recommended actions for a resource in a Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
        /// </summary>
        [Output("onsTopicId")]
        public Output<string> OnsTopicId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
        /// </summary>
        [Output("preferredLanguage")]
        public Output<string> PreferredLanguage { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("preferredTimeZone")]
        public Output<string> PreferredTimeZone { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the announcement subscription.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time that the announcement subscription was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time that the announcement subscription was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a AnnouncementSubscription resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AnnouncementSubscription(string name, AnnouncementSubscriptionArgs args, CustomResourceOptions? options = null)
            : base("oci:AnnouncementsService/announcementSubscription:AnnouncementSubscription", name, args ?? new AnnouncementSubscriptionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AnnouncementSubscription(string name, Input<string> id, AnnouncementSubscriptionState? state = null, CustomResourceOptions? options = null)
            : base("oci:AnnouncementsService/announcementSubscription:AnnouncementSubscription", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing AnnouncementSubscription resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AnnouncementSubscription Get(string name, Input<string> id, AnnouncementSubscriptionState? state = null, CustomResourceOptions? options = null)
        {
            return new AnnouncementSubscription(name, id, state, options);
        }
    }

    public sealed class AnnouncementSubscriptionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A description of the announcement subscription. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
        /// </summary>
        [Input("filterGroups")]
        public Input<Inputs.AnnouncementSubscriptionFilterGroupsArgs>? FilterGroups { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
        /// </summary>
        [Input("onsTopicId", required: true)]
        public Input<string> OnsTopicId { get; set; } = null!;

        /// <summary>
        /// (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
        /// </summary>
        [Input("preferredLanguage")]
        public Input<string>? PreferredLanguage { get; set; }

        /// <summary>
        /// (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("preferredTimeZone")]
        public Input<string>? PreferredTimeZone { get; set; }

        public AnnouncementSubscriptionArgs()
        {
        }
        public static new AnnouncementSubscriptionArgs Empty => new AnnouncementSubscriptionArgs();
    }

    public sealed class AnnouncementSubscriptionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A description of the announcement subscription. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
        /// </summary>
        [Input("filterGroups")]
        public Input<Inputs.AnnouncementSubscriptionFilterGroupsGetArgs>? FilterGroups { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the current lifecycle state in more detail. For example, details might provide required or recommended actions for a resource in a Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
        /// </summary>
        [Input("onsTopicId")]
        public Input<string>? OnsTopicId { get; set; }

        /// <summary>
        /// (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
        /// </summary>
        [Input("preferredLanguage")]
        public Input<string>? PreferredLanguage { get; set; }

        /// <summary>
        /// (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("preferredTimeZone")]
        public Input<string>? PreferredTimeZone { get; set; }

        /// <summary>
        /// The current lifecycle state of the announcement subscription.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time that the announcement subscription was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time that the announcement subscription was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public AnnouncementSubscriptionState()
        {
        }
        public static new AnnouncementSubscriptionState Empty => new AnnouncementSubscriptionState();
    }
}
