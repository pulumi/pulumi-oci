// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class IpsecConnectionTunnelManagementBgpSessionInfoGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The state of the BGP IPv6 session.
        /// </summary>
        [Input("bgpIpv6State")]
        public Input<string>? BgpIpv6State { get; set; }

        [Input("bgpIpv6state")]
        public Input<string>? BgpIpv6state { get; set; }

        /// <summary>
        /// The state of the BGP session.
        /// </summary>
        [Input("bgpState")]
        public Input<string>? BgpState { get; set; }

        /// <summary>
        /// If the tunnel's `routing` attribute is set to `BGP` (see [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnel/)), this ASN is required and used for the tunnel's BGP session. This is the ASN of the network on the CPE end of the BGP session. Can be a 2-byte or 4-byte ASN. Uses "asplain" format.
        /// 
        /// If the tunnel's `routing` attribute is set to `STATIC`, the `customerBgpAsn` must be null.
        /// 
        /// Example: `12345` (2-byte) or `1587232876` (4-byte)
        /// </summary>
        [Input("customerBgpAsn")]
        public Input<string>? CustomerBgpAsn { get; set; }

        /// <summary>
        /// The IP address for the CPE end of the inside tunnel interface.
        /// 
        /// If the tunnel's `routing` attribute is set to `BGP` (see [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnel/)), this IP address is required and used for the tunnel's BGP session.
        /// 
        /// If `routing` is instead set to `STATIC`, this IP address is optional. You can set this IP address to troubleshoot or monitor the tunnel.
        /// 
        /// The value must be a /30 or /31.
        /// 
        /// Example: `10.0.0.5/31`
        /// </summary>
        [Input("customerInterfaceIp")]
        public Input<string>? CustomerInterfaceIp { get; set; }

        /// <summary>
        /// The IPv6 address for the CPE end of the inside tunnel interface. This IP address is optional.
        /// 
        /// If the tunnel's `routing` attribute is set to `BGP` (see [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnectionTunnel/)), this IP address is used for the tunnel's BGP session.
        /// 
        /// If `routing` is instead set to `STATIC`, you can set this IP address to troubleshoot or monitor the tunnel.
        /// 
        /// Only subnet masks from /64 up to /127 are allowed.
        /// 
        /// Example: `2001:db8::1/64`
        /// </summary>
        [Input("customerInterfaceIpv6")]
        public Input<string>? CustomerInterfaceIpv6 { get; set; }

        /// <summary>
        /// The Oracle BGP ASN.
        /// </summary>
        [Input("oracleBgpAsn")]
        public Input<string>? OracleBgpAsn { get; set; }

        /// <summary>
        /// The IP address for the Oracle end of the inside tunnel interface.
        /// 
        /// If the tunnel's `routing` attribute is set to `BGP` (see [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnel/)), this IP address is required and used for the tunnel's BGP session.
        /// 
        /// If `routing` is instead set to `STATIC`, this IP address is optional. You can set this IP address to troubleshoot or monitor the tunnel.
        /// 
        /// The value must be a /30 or /31.
        /// 
        /// Example: `10.0.0.4/31`
        /// </summary>
        [Input("oracleInterfaceIp")]
        public Input<string>? OracleInterfaceIp { get; set; }

        /// <summary>
        /// The IPv6 address for the Oracle end of the inside tunnel interface. This IP address is optional.
        /// 
        /// If the tunnel's `routing` attribute is set to `BGP` (see [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnectionTunnel/)), this IP address is used for the tunnel's BGP session.
        /// 
        /// If `routing` is instead set to `STATIC`, you can set this IP address to troubleshoot or monitor the tunnel.
        /// 
        /// Only subnet masks from /64 up to /127 are allowed.
        /// 
        /// Example: `2001:db8::1/64`
        /// </summary>
        [Input("oracleInterfaceIpv6")]
        public Input<string>? OracleInterfaceIpv6 { get; set; }

        public IpsecConnectionTunnelManagementBgpSessionInfoGetArgs()
        {
        }
        public static new IpsecConnectionTunnelManagementBgpSessionInfoGetArgs Empty => new IpsecConnectionTunnelManagementBgpSessionInfoGetArgs();
    }
}
