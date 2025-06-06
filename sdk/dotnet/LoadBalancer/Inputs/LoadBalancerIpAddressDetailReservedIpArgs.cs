// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class LoadBalancerIpAddressDetailReservedIpArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Ocid of the Reserved IP/Public Ip created with VCN.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public LoadBalancerIpAddressDetailReservedIpArgs()
        {
        }
        public static new LoadBalancerIpAddressDetailReservedIpArgs Empty => new LoadBalancerIpAddressDetailReservedIpArgs();
    }
}
