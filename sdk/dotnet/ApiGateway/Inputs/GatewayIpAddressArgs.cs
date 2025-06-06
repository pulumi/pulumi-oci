// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class GatewayIpAddressArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// An IP address.
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        public GatewayIpAddressArgs()
        {
        }
        public static new GatewayIpAddressArgs Empty => new GatewayIpAddressArgs();
    }
}
