// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetVirtualCircuitCrossConnectMappingResult
    {
        /// <summary>
        /// The key for BGP MD5 authentication. Only applicable if your system requires MD5 authentication. If empty or not set (null), that means you don't use BGP MD5 authentication.
        /// </summary>
        public readonly string BgpMd5authKey;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect or cross-connect group for this mapping. Specified by the owner of the cross-connect or cross-connect group (the customer if the customer is colocated with Oracle, or the provider if the customer is connecting via provider).
        /// </summary>
        public readonly string CrossConnectOrCrossConnectGroupId;
        /// <summary>
        /// The BGP IPv4 address for the router on the other end of the BGP session from Oracle. Specified by the owner of that router. If the session goes from Oracle to a customer, this is the BGP IPv4 address of the customer's edge router. If the session goes from Oracle to a provider, this is the BGP IPv4 address of the provider's edge router. Must use a subnet mask from /28 to /31.
        /// </summary>
        public readonly string CustomerBgpPeeringIp;
        /// <summary>
        /// The BGP IPv6 address for the router on the other end of the BGP session from Oracle. Specified by the owner of that router. If the session goes from Oracle to a customer, this is the BGP IPv6 address of the customer's edge router. If the session goes from Oracle to a provider, this is the BGP IPv6 address of the provider's edge router. Only subnet masks from /64 up to /127 are allowed.
        /// </summary>
        public readonly string CustomerBgpPeeringIpv6;
        /// <summary>
        /// The IPv4 address for Oracle's end of the BGP session. Must use a /30 or /31 subnet mask. If the session goes from Oracle to a customer's edge router, the customer specifies this information. If the session goes from Oracle to a provider's edge router, the provider specifies this.
        /// </summary>
        public readonly string OracleBgpPeeringIp;
        /// <summary>
        /// The IPv6 address for Oracle's end of the BGP session. Only subnet masks from /64 up to /127 are allowed. If the session goes from Oracle to a customer's edge router, the customer specifies this information. If the session goes from Oracle to a provider's edge router, the provider specifies this.
        /// </summary>
        public readonly string OracleBgpPeeringIpv6;
        /// <summary>
        /// The number of the specific VLAN (on the cross-connect or cross-connect group) that is assigned to this virtual circuit. Specified by the owner of the cross-connect or cross-connect group (the customer if the customer is colocated with Oracle, or the provider if the customer is connecting via provider).  Example: `200`
        /// </summary>
        public readonly int Vlan;

        [OutputConstructor]
        private GetVirtualCircuitCrossConnectMappingResult(
            string bgpMd5authKey,

            string crossConnectOrCrossConnectGroupId,

            string customerBgpPeeringIp,

            string customerBgpPeeringIpv6,

            string oracleBgpPeeringIp,

            string oracleBgpPeeringIpv6,

            int vlan)
        {
            BgpMd5authKey = bgpMd5authKey;
            CrossConnectOrCrossConnectGroupId = crossConnectOrCrossConnectGroupId;
            CustomerBgpPeeringIp = customerBgpPeeringIp;
            CustomerBgpPeeringIpv6 = customerBgpPeeringIpv6;
            OracleBgpPeeringIp = oracleBgpPeeringIp;
            OracleBgpPeeringIpv6 = oracleBgpPeeringIpv6;
            Vlan = vlan;
        }
    }
}
