// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Inputs
{

    public sealed class SubscriptionPaymentGatewayGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("merchantDefinedDatas")]
        private InputList<Inputs.SubscriptionPaymentGatewayMerchantDefinedDataGetArgs>? _merchantDefinedDatas;

        /// <summary>
        /// Merchant details.
        /// </summary>
        public InputList<Inputs.SubscriptionPaymentGatewayMerchantDefinedDataGetArgs> MerchantDefinedDatas
        {
            get => _merchantDefinedDatas ?? (_merchantDefinedDatas = new InputList<Inputs.SubscriptionPaymentGatewayMerchantDefinedDataGetArgs>());
            set => _merchantDefinedDatas = value;
        }

        public SubscriptionPaymentGatewayGetArgs()
        {
        }
        public static new SubscriptionPaymentGatewayGetArgs Empty => new SubscriptionPaymentGatewayGetArgs();
    }
}
