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
    public sealed class GetIpsecConnectionTunnelBgpSessionInfoResult
    {
        /// <summary>
        /// The state of the BGP IPv6 session.
        /// </summary>
        public readonly string BgpIpv6State;
        public readonly string BgpIpv6state;
        /// <summary>
        /// the state of the BGP.
        /// </summary>
        public readonly string BgpState;
        /// <summary>
        /// This is the value of the remote Bgp ASN in asplain format, as a string. Example: 1587232876 (4 byte ASN) or 12345 (2 byte ASN)
        /// </summary>
        public readonly string CustomerBgpAsn;
        /// <summary>
        /// This is the IPv4 Address used in the BGP peering session for the non-Oracle router. Example: 10.0.0.2/31
        /// </summary>
        public readonly string CustomerInterfaceIp;
        /// <summary>
        /// The IPv6 address for the CPE end of the inside tunnel interface.
        /// </summary>
        public readonly string CustomerInterfaceIpv6;
        /// <summary>
        /// This is the value of the Oracle Bgp ASN in asplain format, as a string. Example: 1587232876 (4 byte ASN) or 12345 (2 byte ASN)
        /// </summary>
        public readonly string OracleBgpAsn;
        /// <summary>
        /// This is the IPv4 Address used in the BGP peering session for the Oracle router. Example: 10.0.0.1/31
        /// </summary>
        public readonly string OracleInterfaceIp;
        /// <summary>
        /// The IPv6 address for the Oracle end of the inside tunnel interface.
        /// </summary>
        public readonly string OracleInterfaceIpv6;

        [OutputConstructor]
        private GetIpsecConnectionTunnelBgpSessionInfoResult(
            string bgpIpv6State,

            string bgpIpv6state,

            string bgpState,

            string customerBgpAsn,

            string customerInterfaceIp,

            string customerInterfaceIpv6,

            string oracleBgpAsn,

            string oracleInterfaceIp,

            string oracleInterfaceIpv6)
        {
            BgpIpv6State = bgpIpv6State;
            BgpIpv6state = bgpIpv6state;
            BgpState = bgpState;
            CustomerBgpAsn = customerBgpAsn;
            CustomerInterfaceIp = customerInterfaceIp;
            CustomerInterfaceIpv6 = customerInterfaceIpv6;
            OracleBgpAsn = oracleBgpAsn;
            OracleInterfaceIp = oracleInterfaceIp;
            OracleInterfaceIpv6 = oracleInterfaceIpv6;
        }
    }
}
