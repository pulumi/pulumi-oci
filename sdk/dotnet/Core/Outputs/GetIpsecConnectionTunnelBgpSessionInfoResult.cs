// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
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
        /// This is the value of the Oracle Bgp ASN in asplain format, as a string. Example: 1587232876 (4 byte ASN) or 12345 (2 byte ASN)
        /// </summary>
        public readonly string OracleBgpAsn;
        /// <summary>
        /// This is the IPv4 Address used in the BGP peering session for the Oracle router. Example: 10.0.0.1/31
        /// </summary>
        public readonly string OracleInterfaceIp;

        [OutputConstructor]
        private GetIpsecConnectionTunnelBgpSessionInfoResult(
            string bgpIpv6state,

            string bgpState,

            string customerBgpAsn,

            string customerInterfaceIp,

            string oracleBgpAsn,

            string oracleInterfaceIp)
        {
            BgpIpv6state = bgpIpv6state;
            BgpState = bgpState;
            CustomerBgpAsn = customerBgpAsn;
            CustomerInterfaceIp = customerInterfaceIp;
            OracleBgpAsn = oracleBgpAsn;
            OracleInterfaceIp = oracleInterfaceIp;
        }
    }
}