// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ons
{
    /// <summary>
    /// This resource provides the Notification Topic resource in Oracle Cloud Infrastructure Notifications service.
    /// 
    /// Creates a topic in the specified compartment. For general information about topics, see
    /// [Managing Topics and Subscriptions](https://docs.cloud.oracle.com/iaas/Content/Notification/Tasks/managingtopicsandsubscriptions.htm).
    /// 
    /// For the purposes of access control, you must provide the OCID of the compartment where you want the topic to reside.
    /// For information about access control and compartments, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
    /// 
    /// You must specify a display name for the topic.
    /// 
    /// All Oracle Cloud Infrastructure resources, including topics, get an Oracle-assigned, unique ID called an
    /// Oracle Cloud Identifier (OCID). When you create a resource, you can find its OCID in the response. You can also
    /// retrieve a resource's OCID by using a List API operation on that resource type, or by viewing the resource in the
    /// Console. For more information, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    /// 
    /// Transactions Per Minute (TPM) per-tenancy limit for this operation: 60.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testNotificationTopic = new Oci.Ons.NotificationTopic("testNotificationTopic", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = @var.Notification_topic_description,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// NotificationTopics can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Ons/notificationTopic:NotificationTopic test_notification_topic "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Ons/notificationTopic:NotificationTopic")]
    public partial class NotificationTopic : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The endpoint for managing subscriptions or publishing messages to the topic.
        /// </summary>
        [Output("apiEndpoint")]
        public Output<string> ApiEndpoint { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the topic in.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the topic being created. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// For optimistic concurrency control. See `if-match`.
        /// </summary>
        [Output("etag")]
        public Output<string> Etag { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The name of the topic being created. The topic name must be unique across the tenancy. Avoid entering confidential information.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// A unique short topic Id. This is used only for SMS subscriptions.
        /// </summary>
        [Output("shortTopicId")]
        public Output<string> ShortTopicId { get; private set; } = null!;

        /// <summary>
        /// The lifecycle state of the topic.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The time the topic was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic.
        /// </summary>
        [Output("topicId")]
        public Output<string> TopicId { get; private set; } = null!;


        /// <summary>
        /// Create a NotificationTopic resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NotificationTopic(string name, NotificationTopicArgs args, CustomResourceOptions? options = null)
            : base("oci:Ons/notificationTopic:NotificationTopic", name, args ?? new NotificationTopicArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NotificationTopic(string name, Input<string> id, NotificationTopicState? state = null, CustomResourceOptions? options = null)
            : base("oci:Ons/notificationTopic:NotificationTopic", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NotificationTopic resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NotificationTopic Get(string name, Input<string> id, NotificationTopicState? state = null, CustomResourceOptions? options = null)
        {
            return new NotificationTopic(name, id, state, options);
        }
    }

    public sealed class NotificationTopicArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the topic in.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the topic being created. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The name of the topic being created. The topic name must be unique across the tenancy. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public NotificationTopicArgs()
        {
        }
        public static new NotificationTopicArgs Empty => new NotificationTopicArgs();
    }

    public sealed class NotificationTopicState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The endpoint for managing subscriptions or publishing messages to the topic.
        /// </summary>
        [Input("apiEndpoint")]
        public Input<string>? ApiEndpoint { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the topic in.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the topic being created. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// For optimistic concurrency control. See `if-match`.
        /// </summary>
        [Input("etag")]
        public Input<string>? Etag { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The name of the topic being created. The topic name must be unique across the tenancy. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A unique short topic Id. This is used only for SMS subscriptions.
        /// </summary>
        [Input("shortTopicId")]
        public Input<string>? ShortTopicId { get; set; }

        /// <summary>
        /// The lifecycle state of the topic.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The time the topic was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic.
        /// </summary>
        [Input("topicId")]
        public Input<string>? TopicId { get; set; }

        public NotificationTopicState()
        {
        }
        public static new NotificationTopicState Empty => new NotificationTopicState();
    }
}