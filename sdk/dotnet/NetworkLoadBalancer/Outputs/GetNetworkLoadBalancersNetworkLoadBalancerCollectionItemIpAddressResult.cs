// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemIpAddressResult
    {
        /// <summary>
        /// An IP address.  Example: `192.168.0.3`
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// IP version associated with this IP address.
        /// </summary>
        public readonly string IpVersion;
        /// <summary>
        /// Whether the IP address is public or private.
        /// If "true", then the IP address is public and accessible from the internet.
        /// </summary>
        public readonly bool IsPublic;
        /// <summary>
        /// An object representing a reserved IP address to be attached or that is already attached to a network load balancer.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemIpAddressReservedIpResult> ReservedIps;

        [OutputConstructor]
        private GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemIpAddressResult(
            string ipAddress,

            string ipVersion,

            bool isPublic,

            ImmutableArray<Outputs.GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemIpAddressReservedIpResult> reservedIps)
        {
            IpAddress = ipAddress;
            IpVersion = ipVersion;
            IsPublic = isPublic;
            ReservedIps = reservedIps;
        }
    }
}