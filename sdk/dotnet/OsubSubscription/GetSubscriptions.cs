// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsubSubscription
{
    public static class GetSubscriptions
    {
        /// <summary>
        /// This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Osub Subscription service.
        /// 
        /// This list API returns all subscriptions for a given plan number or subscription id or buyer email 
        /// and provides additional parameters to include ratecard and commitment details.
        /// This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
        /// a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testSubscriptions = Oci.OsubSubscription.GetSubscriptions.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         BuyerEmail = @var.Subscription_buyer_email,
        ///         IsCommitInfoRequired = @var.Subscription_is_commit_info_required,
        ///         PlanNumber = @var.Subscription_plan_number,
        ///         SubscriptionId = oci_osub_subscription_subscription.Test_subscription.Id,
        ///         XOneGatewaySubscriptionId = @var.Subscription_x_one_gateway_subscription_id,
        ///         XOneOriginRegion = @var.Subscription_x_one_origin_region,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetSubscriptionsResult> InvokeAsync(GetSubscriptionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetSubscriptionsResult>("oci:OsubSubscription/getSubscriptions:getSubscriptions", args ?? new GetSubscriptionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Osub Subscription service.
        /// 
        /// This list API returns all subscriptions for a given plan number or subscription id or buyer email 
        /// and provides additional parameters to include ratecard and commitment details.
        /// This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
        /// a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testSubscriptions = Oci.OsubSubscription.GetSubscriptions.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         BuyerEmail = @var.Subscription_buyer_email,
        ///         IsCommitInfoRequired = @var.Subscription_is_commit_info_required,
        ///         PlanNumber = @var.Subscription_plan_number,
        ///         SubscriptionId = oci_osub_subscription_subscription.Test_subscription.Id,
        ///         XOneGatewaySubscriptionId = @var.Subscription_x_one_gateway_subscription_id,
        ///         XOneOriginRegion = @var.Subscription_x_one_origin_region,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetSubscriptionsResult> Invoke(GetSubscriptionsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetSubscriptionsResult>("oci:OsubSubscription/getSubscriptions:getSubscriptions", args ?? new GetSubscriptionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSubscriptionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Buyer Email Id
        /// </summary>
        [Input("buyerEmail")]
        public string? BuyerEmail { get; set; }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetSubscriptionsFilterArgs>? _filters;
        public List<Inputs.GetSubscriptionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSubscriptionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Boolean value to decide whether commitment services will be shown
        /// </summary>
        [Input("isCommitInfoRequired")]
        public bool? IsCommitInfoRequired { get; set; }

        /// <summary>
        /// The Plan Number
        /// </summary>
        [Input("planNumber")]
        public string? PlanNumber { get; set; }

        /// <summary>
        /// Line level Subscription Id
        /// </summary>
        [Input("subscriptionId")]
        public string? SubscriptionId { get; set; }

        /// <summary>
        /// This header is meant to be used only for internal purposes and will be ignored on any public request. The purpose of this header is  to help on Gateway to API calls identification.
        /// </summary>
        [Input("xOneGatewaySubscriptionId")]
        public string? XOneGatewaySubscriptionId { get; set; }

        /// <summary>
        /// The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
        /// </summary>
        [Input("xOneOriginRegion")]
        public string? XOneOriginRegion { get; set; }

        public GetSubscriptionsArgs()
        {
        }
        public static new GetSubscriptionsArgs Empty => new GetSubscriptionsArgs();
    }

    public sealed class GetSubscriptionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Buyer Email Id
        /// </summary>
        [Input("buyerEmail")]
        public Input<string>? BuyerEmail { get; set; }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetSubscriptionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetSubscriptionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSubscriptionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Boolean value to decide whether commitment services will be shown
        /// </summary>
        [Input("isCommitInfoRequired")]
        public Input<bool>? IsCommitInfoRequired { get; set; }

        /// <summary>
        /// The Plan Number
        /// </summary>
        [Input("planNumber")]
        public Input<string>? PlanNumber { get; set; }

        /// <summary>
        /// Line level Subscription Id
        /// </summary>
        [Input("subscriptionId")]
        public Input<string>? SubscriptionId { get; set; }

        /// <summary>
        /// This header is meant to be used only for internal purposes and will be ignored on any public request. The purpose of this header is  to help on Gateway to API calls identification.
        /// </summary>
        [Input("xOneGatewaySubscriptionId")]
        public Input<string>? XOneGatewaySubscriptionId { get; set; }

        /// <summary>
        /// The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
        /// </summary>
        [Input("xOneOriginRegion")]
        public Input<string>? XOneOriginRegion { get; set; }

        public GetSubscriptionsInvokeArgs()
        {
        }
        public static new GetSubscriptionsInvokeArgs Empty => new GetSubscriptionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetSubscriptionsResult
    {
        public readonly string? BuyerEmail;
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetSubscriptionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsCommitInfoRequired;
        public readonly string? PlanNumber;
        public readonly string? SubscriptionId;
        /// <summary>
        /// The list of subscriptions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionsSubscriptionResult> Subscriptions;
        public readonly string? XOneGatewaySubscriptionId;
        public readonly string? XOneOriginRegion;

        [OutputConstructor]
        private GetSubscriptionsResult(
            string? buyerEmail,

            string compartmentId,

            ImmutableArray<Outputs.GetSubscriptionsFilterResult> filters,

            string id,

            bool? isCommitInfoRequired,

            string? planNumber,

            string? subscriptionId,

            ImmutableArray<Outputs.GetSubscriptionsSubscriptionResult> subscriptions,

            string? xOneGatewaySubscriptionId,

            string? xOneOriginRegion)
        {
            BuyerEmail = buyerEmail;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            IsCommitInfoRequired = isCommitInfoRequired;
            PlanNumber = planNumber;
            SubscriptionId = subscriptionId;
            Subscriptions = subscriptions;
            XOneGatewaySubscriptionId = xOneGatewaySubscriptionId;
            XOneOriginRegion = xOneOriginRegion;
        }
    }
}