// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DelegateAccessControl
{
    /// <summary>
    /// This resource provides the Delegation Subscription resource in Oracle Cloud Infrastructure Delegate Access Control service.
    /// 
    /// Creates Delegation Subscription in Delegation Control.
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
    ///     var testDelegationSubscription = new Oci.DelegateAccessControl.DelegationSubscription("test_delegation_subscription", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         ServiceProviderId = testServiceProvider.Id,
    ///         SubscribedServiceType = delegationSubscriptionSubscribedServiceType,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = delegationSubscriptionDescription,
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
    /// DelegationSubscriptions can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DelegateAccessControl/delegationSubscription:DelegationSubscription test_delegation_subscription "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DelegateAccessControl/delegationSubscription:DelegationSubscription")]
    public partial class DelegationSubscription : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the Delegation Control.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of the Delegation Subscription.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// Display name
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Description of the current lifecycle state in more detail.
        /// </summary>
        [Output("lifecycleStateDetails")]
        public Output<string> LifecycleStateDetails { get; private set; } = null!;

        /// <summary>
        /// Unique identifier of the Service Provider.
        /// </summary>
        [Output("serviceProviderId")]
        public Output<string> ServiceProviderId { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the Service Provider.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Subscribed Service Provider Service Type.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("subscribedServiceType")]
        public Output<string> SubscribedServiceType { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// Time when the Service Provider was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Time when the Service Provider was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a DelegationSubscription resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DelegationSubscription(string name, DelegationSubscriptionArgs args, CustomResourceOptions? options = null)
            : base("oci:DelegateAccessControl/delegationSubscription:DelegationSubscription", name, args ?? new DelegationSubscriptionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DelegationSubscription(string name, Input<string> id, DelegationSubscriptionState? state = null, CustomResourceOptions? options = null)
            : base("oci:DelegateAccessControl/delegationSubscription:DelegationSubscription", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DelegationSubscription resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DelegationSubscription Get(string name, Input<string> id, DelegationSubscriptionState? state = null, CustomResourceOptions? options = null)
        {
            return new DelegationSubscription(name, id, state, options);
        }
    }

    public sealed class DelegationSubscriptionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the Delegation Control.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Delegation Subscription.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Unique identifier of the Service Provider.
        /// </summary>
        [Input("serviceProviderId", required: true)]
        public Input<string> ServiceProviderId { get; set; } = null!;

        /// <summary>
        /// Subscribed Service Provider Service Type.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("subscribedServiceType", required: true)]
        public Input<string> SubscribedServiceType { get; set; } = null!;

        public DelegationSubscriptionArgs()
        {
        }
        public static new DelegationSubscriptionArgs Empty => new DelegationSubscriptionArgs();
    }

    public sealed class DelegationSubscriptionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the Delegation Control.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Delegation Subscription.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Display name
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Description of the current lifecycle state in more detail.
        /// </summary>
        [Input("lifecycleStateDetails")]
        public Input<string>? LifecycleStateDetails { get; set; }

        /// <summary>
        /// Unique identifier of the Service Provider.
        /// </summary>
        [Input("serviceProviderId")]
        public Input<string>? ServiceProviderId { get; set; }

        /// <summary>
        /// The current lifecycle state of the Service Provider.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Subscribed Service Provider Service Type.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("subscribedServiceType")]
        public Input<string>? SubscribedServiceType { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// Time when the Service Provider was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time when the Service Provider was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DelegationSubscriptionState()
        {
        }
        public static new DelegationSubscriptionState Empty => new DelegationSubscriptionState();
    }
}
