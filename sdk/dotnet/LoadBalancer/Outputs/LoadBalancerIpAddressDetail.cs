// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class LoadBalancerIpAddressDetail
    {
        /// <summary>
        /// An IP address.  Example: `192.168.0.3`
        /// </summary>
        public readonly string? IpAddress;
        /// <summary>
        /// Whether the IP address is public or private.
        /// </summary>
        public readonly bool? IsPublic;
        /// <summary>
        /// Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.LoadBalancerIpAddressDetailReservedIp> ReservedIps;

        [OutputConstructor]
        private LoadBalancerIpAddressDetail(
            string? ipAddress,

            bool? isPublic,

            ImmutableArray<Outputs.LoadBalancerIpAddressDetailReservedIp> reservedIps)
        {
            IpAddress = ipAddress;
            IsPublic = isPublic;
            ReservedIps = reservedIps;
        }
    }
}