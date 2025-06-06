// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Outputs
{

    [OutputType]
    public sealed class GetInvoicesInvoiceCollectionItemLastPaymentDetailResult
    {
        /// <summary>
        /// Account number of the card owner
        /// </summary>
        public readonly string AccountNumber;
        /// <summary>
        /// Amount that paid
        /// </summary>
        public readonly double AmountPaid;
        /// <summary>
        /// Echeck card type
        /// </summary>
        public readonly string CardType;
        /// <summary>
        /// Credit card type
        /// </summary>
        public readonly string CreditCardType;
        /// <summary>
        /// Last four routing digits of the card
        /// </summary>
        public readonly string EcheckRouting;
        /// <summary>
        /// Last four digits of the card
        /// </summary>
        public readonly string LastDigits;
        /// <summary>
        /// Name on the credit card
        /// </summary>
        public readonly string NameOnCard;
        /// <summary>
        /// example
        /// </summary>
        public readonly string PaidBy;
        /// <summary>
        /// Payment method
        /// </summary>
        public readonly string PaymentMethod;
        /// <summary>
        /// The id (email address) of the paypal payment
        /// </summary>
        public readonly string PaypalId;
        /// <summary>
        /// paypal payment reference
        /// </summary>
        public readonly string PaypalReference;
        /// <summary>
        /// Routing number of the echeck card
        /// </summary>
        public readonly string RoutingNumber;
        /// <summary>
        /// Expired date of the credit card
        /// </summary>
        public readonly string TimeExpiration;
        /// <summary>
        /// Paid the invoice on this day
        /// </summary>
        public readonly string TimePaidOn;

        [OutputConstructor]
        private GetInvoicesInvoiceCollectionItemLastPaymentDetailResult(
            string accountNumber,

            double amountPaid,

            string cardType,

            string creditCardType,

            string echeckRouting,

            string lastDigits,

            string nameOnCard,

            string paidBy,

            string paymentMethod,

            string paypalId,

            string paypalReference,

            string routingNumber,

            string timeExpiration,

            string timePaidOn)
        {
            AccountNumber = accountNumber;
            AmountPaid = amountPaid;
            CardType = cardType;
            CreditCardType = creditCardType;
            EcheckRouting = echeckRouting;
            LastDigits = lastDigits;
            NameOnCard = nameOnCard;
            PaidBy = paidBy;
            PaymentMethod = paymentMethod;
            PaypalId = paypalId;
            PaypalReference = paypalReference;
            RoutingNumber = routingNumber;
            TimeExpiration = timeExpiration;
            TimePaidOn = timePaidOn;
        }
    }
}
