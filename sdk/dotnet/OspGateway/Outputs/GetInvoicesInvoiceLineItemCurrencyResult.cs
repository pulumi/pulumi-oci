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
    public sealed class GetInvoicesInvoiceLineItemCurrencyResult
    {
        /// <summary>
        /// Currency code
        /// </summary>
        public readonly string CurrencyCode;
        /// <summary>
        /// Currency symbol
        /// </summary>
        public readonly string CurrencySymbol;
        /// <summary>
        /// Name of the currency
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Round decimal point
        /// </summary>
        public readonly double RoundDecimalPoint;
        /// <summary>
        /// USD conversion rate of the currency
        /// </summary>
        public readonly double UsdConversion;

        [OutputConstructor]
        private GetInvoicesInvoiceLineItemCurrencyResult(
            string currencyCode,

            string currencySymbol,

            string name,

            double roundDecimalPoint,

            double usdConversion)
        {
            CurrencyCode = currencyCode;
            CurrencySymbol = currencySymbol;
            Name = name;
            RoundDecimalPoint = roundDecimalPoint;
            UsdConversion = usdConversion;
        }
    }
}