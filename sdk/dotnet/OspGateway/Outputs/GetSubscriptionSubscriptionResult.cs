// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Outputs
{

    [OutputType]
    public sealed class GetSubscriptionSubscriptionResult
    {
        /// <summary>
        /// Bill to customer Account id.
        /// </summary>
        public readonly string BillToCustAccountId;
        /// <summary>
        /// Billing address details model.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionSubscriptionBillingAddressResult> BillingAddresses;
        /// <summary>
        /// Currency code
        /// </summary>
        public readonly string CurrencyCode;
        /// <summary>
        /// GSI Subscription external code.
        /// </summary>
        public readonly string GsiOrgCode;
        /// <summary>
        /// Subscription id identifier (OCID).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Payment intension.
        /// </summary>
        public readonly bool IsIntentToPay;
        /// <summary>
        /// Language short code (en, de, hu, etc)
        /// </summary>
        public readonly string LanguageCode;
        /// <summary>
        /// GSI organization external identifier.
        /// </summary>
        public readonly string OrganizationId;
        /// <summary>
        /// Payment gateway details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionSubscriptionPaymentGatewayResult> PaymentGateways;
        /// <summary>
        /// Payment option list of a subscription.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionSubscriptionPaymentOptionResult> PaymentOptions;
        /// <summary>
        /// Subscription plan type.
        /// </summary>
        public readonly string PlanType;
        /// <summary>
        /// Ship to customer account role.
        /// </summary>
        public readonly string ShipToCustAcctRoleId;
        /// <summary>
        /// Ship to customer account site address id.
        /// </summary>
        public readonly string ShipToCustAcctSiteId;
        /// <summary>
        /// Subscription plan number.
        /// </summary>
        public readonly string SubscriptionPlanNumber;
        /// <summary>
        /// Tax details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSubscriptionSubscriptionTaxInfoResult> TaxInfos;
        /// <summary>
        /// Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
        /// </summary>
        public readonly string TimePlanUpgrade;
        /// <summary>
        /// Start date of the subscription.
        /// </summary>
        public readonly string TimeStart;
        /// <summary>
        /// Status of the upgrade.
        /// </summary>
        public readonly string UpgradeState;
        /// <summary>
        /// This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
        /// </summary>
        public readonly string UpgradeStateDetails;

        [OutputConstructor]
        private GetSubscriptionSubscriptionResult(
            string billToCustAccountId,

            ImmutableArray<Outputs.GetSubscriptionSubscriptionBillingAddressResult> billingAddresses,

            string currencyCode,

            string gsiOrgCode,

            string id,

            bool isIntentToPay,

            string languageCode,

            string organizationId,

            ImmutableArray<Outputs.GetSubscriptionSubscriptionPaymentGatewayResult> paymentGateways,

            ImmutableArray<Outputs.GetSubscriptionSubscriptionPaymentOptionResult> paymentOptions,

            string planType,

            string shipToCustAcctRoleId,

            string shipToCustAcctSiteId,

            string subscriptionPlanNumber,

            ImmutableArray<Outputs.GetSubscriptionSubscriptionTaxInfoResult> taxInfos,

            string timePlanUpgrade,

            string timeStart,

            string upgradeState,

            string upgradeStateDetails)
        {
            BillToCustAccountId = billToCustAccountId;
            BillingAddresses = billingAddresses;
            CurrencyCode = currencyCode;
            GsiOrgCode = gsiOrgCode;
            Id = id;
            IsIntentToPay = isIntentToPay;
            LanguageCode = languageCode;
            OrganizationId = organizationId;
            PaymentGateways = paymentGateways;
            PaymentOptions = paymentOptions;
            PlanType = planType;
            ShipToCustAcctRoleId = shipToCustAcctRoleId;
            ShipToCustAcctSiteId = shipToCustAcctSiteId;
            SubscriptionPlanNumber = subscriptionPlanNumber;
            TaxInfos = taxInfos;
            TimePlanUpgrade = timePlanUpgrade;
            TimeStart = timeStart;
            UpgradeState = upgradeState;
            UpgradeStateDetails = upgradeStateDetails;
        }
    }
}