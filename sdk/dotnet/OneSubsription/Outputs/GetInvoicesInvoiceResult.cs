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
    public sealed class GetInvoicesInvoiceResult
    {
        /// <summary>
        /// AR Invoice Numbers comma separated under one invoice
        /// </summary>
        public readonly string ArInvoices;
        /// <summary>
        /// Address.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceBillToAddressResult> BillToAddresses;
        /// <summary>
        /// User.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceBillToContactResult> BillToContacts;
        /// <summary>
        /// Business partner.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceBillToCustomerResult> BillToCustomers;
        /// <summary>
        /// User that created the Payment term
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Currency details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceCurrencyResult> Currencies;
        /// <summary>
        /// Invoice Lines under particular invoice.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceInvoiceLineResult> InvoiceLines;
        /// <summary>
        /// Organization details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoiceOrganizationResult> Organizations;
        /// <summary>
        /// Payment Method
        /// </summary>
        public readonly string PaymentMethod;
        /// <summary>
        /// Payment Term details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoicesInvoicePaymentTermResult> PaymentTerms;
        /// <summary>
        /// Receipt Method of Payment Mode
        /// </summary>
        public readonly string ReceiptMethod;
        /// <summary>
        /// SPM Document Number is an functional identifier for invoice in SPM
        /// </summary>
        public readonly string SpmInvoiceNumber;
        /// <summary>
        /// Document Status in SPM which depicts current state of invoice
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Invoice associated subscription plan number.
        /// </summary>
        public readonly string SubscriptionNumber;
        /// <summary>
        /// SPM Invocie creation date
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Invoice Date
        /// </summary>
        public readonly string TimeInvoiceDate;
        /// <summary>
        /// SPM Invoice updated date
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Document Type in SPM like SPM Invoice,SPM Credit Memo etc.,
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// User that updated SPM Invoice
        /// </summary>
        public readonly string UpdatedBy;

        [OutputConstructor]
        private GetInvoicesInvoiceResult(
            string arInvoices,

            ImmutableArray<Outputs.GetInvoicesInvoiceBillToAddressResult> billToAddresses,

            ImmutableArray<Outputs.GetInvoicesInvoiceBillToContactResult> billToContacts,

            ImmutableArray<Outputs.GetInvoicesInvoiceBillToCustomerResult> billToCustomers,

            string createdBy,

            ImmutableArray<Outputs.GetInvoicesInvoiceCurrencyResult> currencies,

            ImmutableArray<Outputs.GetInvoicesInvoiceInvoiceLineResult> invoiceLines,

            ImmutableArray<Outputs.GetInvoicesInvoiceOrganizationResult> organizations,

            string paymentMethod,

            ImmutableArray<Outputs.GetInvoicesInvoicePaymentTermResult> paymentTerms,

            string receiptMethod,

            string spmInvoiceNumber,

            string status,

            string subscriptionNumber,

            string timeCreated,

            string timeInvoiceDate,

            string timeUpdated,

            string type,

            string updatedBy)
        {
            ArInvoices = arInvoices;
            BillToAddresses = billToAddresses;
            BillToContacts = billToContacts;
            BillToCustomers = billToCustomers;
            CreatedBy = createdBy;
            Currencies = currencies;
            InvoiceLines = invoiceLines;
            Organizations = organizations;
            PaymentMethod = paymentMethod;
            PaymentTerms = paymentTerms;
            ReceiptMethod = receiptMethod;
            SpmInvoiceNumber = spmInvoiceNumber;
            Status = status;
            SubscriptionNumber = subscriptionNumber;
            TimeCreated = timeCreated;
            TimeInvoiceDate = timeInvoiceDate;
            TimeUpdated = timeUpdated;
            Type = type;
            UpdatedBy = updatedBy;
        }
    }
}
