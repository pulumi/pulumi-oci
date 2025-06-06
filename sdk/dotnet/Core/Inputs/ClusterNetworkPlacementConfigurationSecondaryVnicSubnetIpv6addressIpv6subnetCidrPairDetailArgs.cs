// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Optional. Used to disambiguate which subnet prefix should be used to create an IPv6 allocation.
        /// </summary>
        [Input("ipv6subnetCidr")]
        public Input<string>? Ipv6subnetCidr { get; set; }

        public ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs()
        {
        }
        public static new ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs Empty => new ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs();
    }
}
