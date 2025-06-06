// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OneSubsription.Outputs
{

    [OutputType]
    public sealed class GetSubscribedServicesSubscribedServiceRateCardResult
    {
        /// <summary>
        /// Currency details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardCurrencyResult> Currencies;
        /// <summary>
        /// Rate card discretionary discount percentage
        /// </summary>
        public readonly string DiscretionaryDiscountPercentage;
        /// <summary>
        /// Rate card price tier flag
        /// </summary>
        public readonly bool IsTier;
        /// <summary>
        /// Rate card tier net unit price
        /// </summary>
        public readonly string NetUnitPrice;
        /// <summary>
        /// Rate card tier overage price
        /// </summary>
        public readonly string OveragePrice;
        /// <summary>
        /// Product description
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardProductResult> Products;
        /// <summary>
        /// List of tiered rate card prices
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardRateCardTierResult> RateCardTiers;
        /// <summary>
        /// SPM internal Subscribed Service ID
        /// </summary>
        public readonly string SubscribedServiceId;
        /// <summary>
        /// Subscribed service end date
        /// </summary>
        public readonly string TimeEnd;
        /// <summary>
        /// Subscribed service start date
        /// </summary>
        public readonly string TimeStart;

        [OutputConstructor]
        private GetSubscribedServicesSubscribedServiceRateCardResult(
            ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardCurrencyResult> currencies,

            string discretionaryDiscountPercentage,

            bool isTier,

            string netUnitPrice,

            string overagePrice,

            ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardProductResult> products,

            ImmutableArray<Outputs.GetSubscribedServicesSubscribedServiceRateCardRateCardTierResult> rateCardTiers,

            string subscribedServiceId,

            string timeEnd,

            string timeStart)
        {
            Currencies = currencies;
            DiscretionaryDiscountPercentage = discretionaryDiscountPercentage;
            IsTier = isTier;
            NetUnitPrice = netUnitPrice;
            OveragePrice = overagePrice;
            Products = products;
            RateCardTiers = rateCardTiers;
            SubscribedServiceId = subscribedServiceId;
            TimeEnd = timeEnd;
            TimeStart = timeStart;
        }
    }
}
