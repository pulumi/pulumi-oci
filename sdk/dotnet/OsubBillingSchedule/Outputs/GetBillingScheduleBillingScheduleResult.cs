// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsubBillingSchedule.Outputs
{

    [OutputType]
    public sealed class GetBillingScheduleBillingScheduleResult
    {
        /// <summary>
        /// Billing schedule line net amount
        /// </summary>
        public readonly string Amount;
        /// <summary>
        /// Indicates the associated AR Customer transaction id a unique identifier existing on AR.
        /// </summary>
        public readonly string ArCustomerTransactionId;
        /// <summary>
        /// Indicates the associated AR Invoice Number
        /// </summary>
        public readonly string ArInvoiceNumber;
        /// <summary>
        /// Billing frequency
        /// </summary>
        public readonly string BillingFrequency;
        /// <summary>
        /// Billing schedule invoice status
        /// </summary>
        public readonly string InvoiceStatus;
        /// <summary>
        /// Billing schedule net unit price
        /// </summary>
        public readonly string NetUnitPrice;
        /// <summary>
        /// Order number associated with the Subscribed Service
        /// </summary>
        public readonly string OrderNumber;
        /// <summary>
        /// Product description
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBillingScheduleBillingScheduleProductResult> Products;
        /// <summary>
        /// Billing schedule quantity
        /// </summary>
        public readonly string Quantity;
        /// <summary>
        /// Billing schedule end date
        /// </summary>
        public readonly string TimeEnd;
        /// <summary>
        /// Billing schedule invoicing date
        /// </summary>
        public readonly string TimeInvoicing;
        /// <summary>
        /// Billing schedule start date
        /// </summary>
        public readonly string TimeStart;

        [OutputConstructor]
        private GetBillingScheduleBillingScheduleResult(
            string amount,

            string arCustomerTransactionId,

            string arInvoiceNumber,

            string billingFrequency,

            string invoiceStatus,

            string netUnitPrice,

            string orderNumber,

            ImmutableArray<Outputs.GetBillingScheduleBillingScheduleProductResult> products,

            string quantity,

            string timeEnd,

            string timeInvoicing,

            string timeStart)
        {
            Amount = amount;
            ArCustomerTransactionId = arCustomerTransactionId;
            ArInvoiceNumber = arInvoiceNumber;
            BillingFrequency = billingFrequency;
            InvoiceStatus = invoiceStatus;
            NetUnitPrice = netUnitPrice;
            OrderNumber = orderNumber;
            Products = products;
            Quantity = quantity;
            TimeEnd = timeEnd;
            TimeInvoicing = timeInvoicing;
            TimeStart = timeStart;
        }
    }
}