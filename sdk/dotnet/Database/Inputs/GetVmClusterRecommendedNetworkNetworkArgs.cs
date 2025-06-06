// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class GetVmClusterRecommendedNetworkNetworkInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The cidr for the network.
        /// </summary>
        [Input("cidr", required: true)]
        public Input<string> Cidr { get; set; } = null!;

        /// <summary>
        /// The network domain name.
        /// </summary>
        [Input("domain", required: true)]
        public Input<string> Domain { get; set; } = null!;

        /// <summary>
        /// The network gateway.
        /// </summary>
        [Input("gateway", required: true)]
        public Input<string> Gateway { get; set; } = null!;

        /// <summary>
        /// The network netmask.
        /// </summary>
        [Input("netmask", required: true)]
        public Input<string> Netmask { get; set; } = null!;

        /// <summary>
        /// The network type.
        /// </summary>
        [Input("networkType", required: true)]
        public Input<string> NetworkType { get; set; } = null!;

        /// <summary>
        /// The network domain name.
        /// </summary>
        [Input("prefix", required: true)]
        public Input<string> Prefix { get; set; } = null!;

        /// <summary>
        /// The network VLAN ID.
        /// </summary>
        [Input("vlanId", required: true)]
        public Input<string> VlanId { get; set; } = null!;

        public GetVmClusterRecommendedNetworkNetworkInputArgs()
        {
        }
        public static new GetVmClusterRecommendedNetworkNetworkInputArgs Empty => new GetVmClusterRecommendedNetworkNetworkInputArgs();
    }
}
