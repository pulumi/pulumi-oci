// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class LoadBalancerIpAddressDetailGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// An IP address.  Example: `192.168.0.3`
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        /// <summary>
        /// Whether the IP address is public or private.
        /// </summary>
        [Input("isPublic")]
        public Input<bool>? IsPublic { get; set; }

        [Input("reservedIps")]
        private InputList<Inputs.LoadBalancerIpAddressDetailReservedIpGetArgs>? _reservedIps;

        /// <summary>
        /// Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
        /// </summary>
        public InputList<Inputs.LoadBalancerIpAddressDetailReservedIpGetArgs> ReservedIps
        {
            get => _reservedIps ?? (_reservedIps = new InputList<Inputs.LoadBalancerIpAddressDetailReservedIpGetArgs>());
            set => _reservedIps = value;
        }

        public LoadBalancerIpAddressDetailGetArgs()
        {
        }
    }
}
