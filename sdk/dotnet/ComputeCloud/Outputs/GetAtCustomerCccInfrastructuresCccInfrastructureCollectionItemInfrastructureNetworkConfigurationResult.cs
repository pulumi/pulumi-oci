// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud.Outputs
{

    [OutputType]
    public sealed class GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationResult
    {
        /// <summary>
        /// The domain name system (DNS) addresses that the Compute Cloud@Customer infrastructure uses for the data center network.
        /// </summary>
        public readonly ImmutableArray<string> DnsIps;
        /// <summary>
        /// Dynamic routing information for the Compute Cloud@Customer infrastructure.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingDynamicResult> InfrastructureRoutingDynamics;
        /// <summary>
        /// Static routing information for a rack.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingStaticResult> InfrastructureRoutingStatics;
        /// <summary>
        /// Information about the management nodes that are provisioned in the Compute Cloud@Customer infrastructure.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNodeResult> ManagementNodes;
        /// <summary>
        /// The hostname corresponding to the virtual IP (VIP) address of the management nodes.
        /// </summary>
        public readonly string MgmtVipHostname;
        /// <summary>
        /// The IP address used as the virtual IP (VIP) address of the management nodes.
        /// </summary>
        public readonly string MgmtVipIp;
        /// <summary>
        /// Addresses of the network spine switches.
        /// </summary>
        public readonly ImmutableArray<string> SpineIps;
        /// <summary>
        /// The spine switch public virtual IP (VIP). Traffic routed to the Compute Cloud@Customer infrastructure and  and virtual cloud networks (VCNs) should have this address as next hop.
        /// </summary>
        public readonly string SpineVip;
        /// <summary>
        /// Domain name to be used as the base domain for the internal network and by  public facing services.
        /// </summary>
        public readonly string UplinkDomain;
        /// <summary>
        /// Uplink gateway in the datacenter network that the Compute Cloud@Customer connects to.
        /// </summary>
        public readonly string UplinkGatewayIp;
        /// <summary>
        /// Netmask of the subnet that the Compute Cloud@Customer infrastructure is connected to.
        /// </summary>
        public readonly string UplinkNetmask;
        /// <summary>
        /// Number of uplink ports per spine switch. Connectivity is identical on both spine switches. For example, if input is two 100 gigabyte ports; then port-1 and port-2 on both spines will be configured.
        /// </summary>
        public readonly int UplinkPortCount;
        /// <summary>
        /// The port forward error correction (FEC) setting for the uplink port on the Compute Cloud@Customer infrastructure.
        /// </summary>
        public readonly string UplinkPortForwardErrorCorrection;
        /// <summary>
        /// Uplink port speed defined in gigabytes per second. All uplink ports must have identical speed.
        /// </summary>
        public readonly int UplinkPortSpeedInGbps;
        /// <summary>
        /// The virtual local area network (VLAN) maximum transmission unit (MTU) size for the uplink ports.
        /// </summary>
        public readonly int UplinkVlanMtu;

        [OutputConstructor]
        private GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationResult(
            ImmutableArray<string> dnsIps,

            ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingDynamicResult> infrastructureRoutingDynamics,

            ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingStaticResult> infrastructureRoutingStatics,

            ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNodeResult> managementNodes,

            string mgmtVipHostname,

            string mgmtVipIp,

            ImmutableArray<string> spineIps,

            string spineVip,

            string uplinkDomain,

            string uplinkGatewayIp,

            string uplinkNetmask,

            int uplinkPortCount,

            string uplinkPortForwardErrorCorrection,

            int uplinkPortSpeedInGbps,

            int uplinkVlanMtu)
        {
            DnsIps = dnsIps;
            InfrastructureRoutingDynamics = infrastructureRoutingDynamics;
            InfrastructureRoutingStatics = infrastructureRoutingStatics;
            ManagementNodes = managementNodes;
            MgmtVipHostname = mgmtVipHostname;
            MgmtVipIp = mgmtVipIp;
            SpineIps = spineIps;
            SpineVip = spineVip;
            UplinkDomain = uplinkDomain;
            UplinkGatewayIp = uplinkGatewayIp;
            UplinkNetmask = uplinkNetmask;
            UplinkPortCount = uplinkPortCount;
            UplinkPortForwardErrorCorrection = uplinkPortForwardErrorCorrection;
            UplinkPortSpeedInGbps = uplinkPortSpeedInGbps;
            UplinkVlanMtu = uplinkVlanMtu;
        }
    }
}