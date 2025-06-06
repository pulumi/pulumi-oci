// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.VnMonitoring.Outputs
{

    [OutputType]
    public sealed class PathAnalysiDestinationEndpoint
    {
        /// <summary>
        /// The IPv4 address of the COMPUTE_INSTANCE-type `Endpoint` object.
        /// </summary>
        public readonly string? Address;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute instance.
        /// </summary>
        public readonly string? InstanceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer listener.
        /// </summary>
        public readonly string? ListenerId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the listener's load balancer.
        /// </summary>
        public readonly string? LoadBalancerId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the listener's network load balancer.
        /// </summary>
        public readonly string? NetworkLoadBalancerId;
        public readonly string? State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet containing the IP address. This can be used to disambiguate which subnet is intended, in case the IP address is used in more than one subnet (when there are subnets with overlapping IP ranges).
        /// </summary>
        public readonly string? SubnetId;
        /// <summary>
        /// The type of the `Endpoint`.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN containing the IP address. This can be used to disambiguate which VLAN is queried, in case the endpoint IP address belongs to more than one VLAN (when there are VLANs with overlapping IP ranges).
        /// </summary>
        public readonly string? VlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC attached to the compute instance.
        /// </summary>
        public readonly string? VnicId;

        [OutputConstructor]
        private PathAnalysiDestinationEndpoint(
            string? address,

            string? instanceId,

            string? listenerId,

            string? loadBalancerId,

            string? networkLoadBalancerId,

            string? state,

            string? subnetId,

            string type,

            string? vlanId,

            string? vnicId)
        {
            Address = address;
            InstanceId = instanceId;
            ListenerId = listenerId;
            LoadBalancerId = loadBalancerId;
            NetworkLoadBalancerId = networkLoadBalancerId;
            State = state;
            SubnetId = subnetId;
            Type = type;
            VlanId = vlanId;
            VnicId = vnicId;
        }
    }
}
