// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Inputs
{

    public sealed class SubscriptionSubscriptionPaymentGatewayGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Merchant details.
        /// </summary>
        [Input("merchantDefinedData")]
        public Input<Inputs.SubscriptionSubscriptionPaymentGatewayMerchantDefinedDataGetArgs>? MerchantDefinedData { get; set; }

        public SubscriptionSubscriptionPaymentGatewayGetArgs()
        {
        }
        public static new SubscriptionSubscriptionPaymentGatewayGetArgs Empty => new SubscriptionSubscriptionPaymentGatewayGetArgs();
    }
}
