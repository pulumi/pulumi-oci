// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy
{
    public static class GetSubscriptionProduct
    {
        /// <summary>
        /// This data source provides details about a specific Subscription Product resource in Oracle Cloud Infrastructure Usage Proxy service.
        /// 
        /// Provides product information that is specific to a reward usage period and its usage details.
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
        ///     var testSubscriptionProduct = Oci.UsageProxy.GetSubscriptionProduct.Invoke(new()
        ///     {
        ///         SubscriptionId = testSubscription.Id,
        ///         TenancyId = testTenancy.Id,
        ///         UsagePeriodKey = subscriptionProductUsagePeriodKey,
        ///         Producttype = subscriptionProductProducttype,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSubscriptionProductResult> InvokeAsync(GetSubscriptionProductArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSubscriptionProductResult>("oci:UsageProxy/getSubscriptionProduct:getSubscriptionProduct", args ?? new GetSubscriptionProductArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Subscription Product resource in Oracle Cloud Infrastructure Usage Proxy service.
        /// 
        /// Provides product information that is specific to a reward usage period and its usage details.
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
        ///     var testSubscriptionProduct = Oci.UsageProxy.GetSubscriptionProduct.Invoke(new()
        ///     {
        ///         SubscriptionId = testSubscription.Id,
        ///         TenancyId = testTenancy.Id,
        ///         UsagePeriodKey = subscriptionProductUsagePeriodKey,
        ///         Producttype = subscriptionProductProducttype,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSubscriptionProductResult> Invoke(GetSubscriptionProductInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSubscriptionProductResult>("oci:UsageProxy/getSubscriptionProduct:getSubscriptionProduct", args ?? new GetSubscriptionProductInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Subscription Product resource in Oracle Cloud Infrastructure Usage Proxy service.
        /// 
        /// Provides product information that is specific to a reward usage period and its usage details.
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
        ///     var testSubscriptionProduct = Oci.UsageProxy.GetSubscriptionProduct.Invoke(new()
        ///     {
        ///         SubscriptionId = testSubscription.Id,
        ///         TenancyId = testTenancy.Id,
        ///         UsagePeriodKey = subscriptionProductUsagePeriodKey,
        ///         Producttype = subscriptionProductProducttype,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSubscriptionProductResult> Invoke(GetSubscriptionProductInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSubscriptionProductResult>("oci:UsageProxy/getSubscriptionProduct:getSubscriptionProduct", args ?? new GetSubscriptionProductInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSubscriptionProductArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The field to specify the type of product.
        /// </summary>
        [Input("producttype")]
        public string? Producttype { get; set; }

        /// <summary>
        /// The subscription ID for which rewards information is requested for.
        /// </summary>
        [Input("subscriptionId", required: true)]
        public string SubscriptionId { get; set; } = null!;

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId", required: true)]
        public string TenancyId { get; set; } = null!;

        /// <summary>
        /// The SPM Identifier for the usage period.
        /// </summary>
        [Input("usagePeriodKey", required: true)]
        public string UsagePeriodKey { get; set; } = null!;

        public GetSubscriptionProductArgs()
        {
        }
        public static new GetSubscriptionProductArgs Empty => new GetSubscriptionProductArgs();
    }

    public sealed class GetSubscriptionProductInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The field to specify the type of product.
        /// </summary>
        [Input("producttype")]
        public Input<string>? Producttype { get; set; }

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
        /// The SPM Identifier for the usage period.
        /// </summary>
        [Input("usagePeriodKey", required: true)]
        public Input<string> UsagePeriodKey { get; set; } = null!;

        public GetSubscriptionProductInvokeArgs()
        {
        }
        public static new GetSubscriptionProductInvokeArgs Empty => new GetSubscriptionProductInvokeArgs();
    }


    [OutputType]
    public sealed class GetSubscriptionProductResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of product rewards summaries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionProductItemResult> Items;
        public readonly string? Producttype;
        public readonly string SubscriptionId;
        public readonly string TenancyId;
        public readonly string UsagePeriodKey;

        [OutputConstructor]
        private GetSubscriptionProductResult(
            string id,

            ImmutableArray<Outputs.GetSubscriptionProductItemResult> items,

            string? producttype,

            string subscriptionId,

            string tenancyId,

            string usagePeriodKey)
        {
            Id = id;
            Items = items;
            Producttype = producttype;
            SubscriptionId = subscriptionId;
            TenancyId = tenancyId;
            UsagePeriodKey = usagePeriodKey;
        }
    }
}
