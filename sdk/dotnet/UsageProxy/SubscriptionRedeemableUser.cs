// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy
{
    /// <summary>
    /// This resource provides the Subscription Redeemable User resource in Oracle Cloud Infrastructure Usage Proxy service.
    /// 
    /// Adds the list of redeemable user summary for a subscription ID.
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
    ///     var testSubscriptionRedeemableUser = new Oci.UsageProxy.SubscriptionRedeemableUser("test_subscription_redeemable_user", new()
    ///     {
    ///         SubscriptionId = testSubscription.Id,
    ///         TenancyId = testTenancy.Id,
    ///         Items = new[]
    ///         {
    ///             new Oci.UsageProxy.Inputs.SubscriptionRedeemableUserItemArgs
    ///             {
    ///                 EmailId = testEmail.Id,
    ///                 FirstName = subscriptionRedeemableUserItemsFirstName,
    ///                 LastName = subscriptionRedeemableUserItemsLastName,
    ///             },
    ///         },
    ///         UserId = testUser.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// SubscriptionRedeemableUsers can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser test_subscription_redeemable_user "subscriptions/{subscriptionId}/redeemableUsers/tenancyId/{tenancyId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser")]
    public partial class SubscriptionRedeemableUser : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The list of new user to be added to the list of user that can redeem rewards.
        /// </summary>
        [Output("items")]
        public Output<ImmutableArray<Outputs.SubscriptionRedeemableUserItem>> Items { get; private set; } = null!;

        /// <summary>
        /// The subscription ID for which rewards information is requested for.
        /// </summary>
        [Output("subscriptionId")]
        public Output<string> SubscriptionId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Output("tenancyId")]
        public Output<string> TenancyId { get; private set; } = null!;

        /// <summary>
        /// The user ID of the person to send a copy of an email.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("userId")]
        public Output<string> UserId { get; private set; } = null!;


        /// <summary>
        /// Create a SubscriptionRedeemableUser resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SubscriptionRedeemableUser(string name, SubscriptionRedeemableUserArgs args, CustomResourceOptions? options = null)
            : base("oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser", name, args ?? new SubscriptionRedeemableUserArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SubscriptionRedeemableUser(string name, Input<string> id, SubscriptionRedeemableUserState? state = null, CustomResourceOptions? options = null)
            : base("oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SubscriptionRedeemableUser resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SubscriptionRedeemableUser Get(string name, Input<string> id, SubscriptionRedeemableUserState? state = null, CustomResourceOptions? options = null)
        {
            return new SubscriptionRedeemableUser(name, id, state, options);
        }
    }

    public sealed class SubscriptionRedeemableUserArgs : global::Pulumi.ResourceArgs
    {
        [Input("items", required: true)]
        private InputList<Inputs.SubscriptionRedeemableUserItemArgs>? _items;

        /// <summary>
        /// The list of new user to be added to the list of user that can redeem rewards.
        /// </summary>
        public InputList<Inputs.SubscriptionRedeemableUserItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.SubscriptionRedeemableUserItemArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The subscription ID for which rewards information is requested for.
        /// </summary>
        [Input("subscriptionId", required: true)]
        public Input<string> SubscriptionId { get; set; } = null!;

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId", required: true)]
        public Input<string> TenancyId { get; set; } = null!;

        /// <summary>
        /// The user ID of the person to send a copy of an email.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public SubscriptionRedeemableUserArgs()
        {
        }
        public static new SubscriptionRedeemableUserArgs Empty => new SubscriptionRedeemableUserArgs();
    }

    public sealed class SubscriptionRedeemableUserState : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.SubscriptionRedeemableUserItemGetArgs>? _items;

        /// <summary>
        /// The list of new user to be added to the list of user that can redeem rewards.
        /// </summary>
        public InputList<Inputs.SubscriptionRedeemableUserItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.SubscriptionRedeemableUserItemGetArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The subscription ID for which rewards information is requested for.
        /// </summary>
        [Input("subscriptionId")]
        public Input<string>? SubscriptionId { get; set; }

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId")]
        public Input<string>? TenancyId { get; set; }

        /// <summary>
        /// The user ID of the person to send a copy of an email.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public SubscriptionRedeemableUserState()
        {
        }
        public static new SubscriptionRedeemableUserState Empty => new SubscriptionRedeemableUserState();
    }
}
