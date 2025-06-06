// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Inputs
{

    public sealed class SubscriptionSubscriptionTaxInfoGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Tax exemption reason code.
        /// </summary>
        [Input("noTaxReasonCode")]
        public Input<string>? NoTaxReasonCode { get; set; }

        /// <summary>
        /// (Updatable) Tax exemption reason description.
        /// </summary>
        [Input("noTaxReasonCodeDetails")]
        public Input<string>? NoTaxReasonCodeDetails { get; set; }

        /// <summary>
        /// (Updatable) Brazilian companies' CNPJ number.
        /// </summary>
        [Input("taxCnpj")]
        public Input<string>? TaxCnpj { get; set; }

        /// <summary>
        /// (Updatable) Tay payer identifier.
        /// </summary>
        [Input("taxPayerId")]
        public Input<string>? TaxPayerId { get; set; }

        /// <summary>
        /// (Updatable) Tax registration number.
        /// </summary>
        [Input("taxRegNumber")]
        public Input<string>? TaxRegNumber { get; set; }

        public SubscriptionSubscriptionTaxInfoGetArgs()
        {
        }
        public static new SubscriptionSubscriptionTaxInfoGetArgs Empty => new SubscriptionSubscriptionTaxInfoGetArgs();
    }
}
