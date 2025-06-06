// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class VirtualCircuitCrossConnectMappingArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The key for BGP MD5 authentication. Only applicable if your system requires MD5 authentication. If empty or not set (null), that means you don't use BGP MD5 authentication.
        /// </summary>
        [Input("bgpMd5authKey")]
        public Input<string>? BgpMd5authKey { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect or cross-connect group for this mapping. Specified by the owner of the cross-connect or cross-connect group (the customer if the customer is colocated with Oracle, or the provider if the customer is connecting via provider).
        /// </summary>
        [Input("crossConnectOrCrossConnectGroupId")]
        public Input<string>? CrossConnectOrCrossConnectGroupId { get; set; }

        /// <summary>
        /// (Updatable) The BGP IPv4 address for the router on the other end of the BGP session from Oracle. Specified by the owner of that router. If the session goes from Oracle to a customer, this is the BGP IPv4 address of the customer's edge router. If the session goes from Oracle to a provider, this is the BGP IPv4 address of the provider's edge router. Must use a subnet mask from /28 to /31.
        /// 
        /// There's one exception: for a public virtual circuit, Oracle specifies the BGP IPv4 addresses.
        /// 
        /// Example: `10.0.0.18/31`
        /// </summary>
        [Input("customerBgpPeeringIp")]
        public Input<string>? CustomerBgpPeeringIp { get; set; }

        /// <summary>
        /// (Updatable) IPv6 is currently supported only in the Government Cloud. The BGP IPv6 address for the router on the other end of the BGP session from Oracle. Specified by the owner of that router. If the session goes from Oracle to a customer, this is the BGP IPv6 address of the customer's edge router. If the session goes from Oracle to a provider, this is the BGP IPv6 address of the provider's edge router. Only subnet masks from /64 up to /127 are allowed.
        /// 
        /// There's one exception: for a public virtual circuit, Oracle specifies the BGP IPv6 addresses.
        /// 
        /// IPv6 addressing is supported for all commercial and government regions. See [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
        /// 
        /// Example: `2001:db8::1/64`
        /// </summary>
        [Input("customerBgpPeeringIpv6")]
        public Input<string>? CustomerBgpPeeringIpv6 { get; set; }

        /// <summary>
        /// (Updatable) The IPv4 address for Oracle's end of the BGP session. Must use a subnet mask from /28 to /31. If the session goes from Oracle to a customer's edge router, the customer specifies this information. If the session goes from Oracle to a provider's edge router, the provider specifies this.
        /// 
        /// There's one exception: for a public virtual circuit, Oracle specifies the BGP IPv4 addresses.
        /// 
        /// Example: `10.0.0.19/31`
        /// </summary>
        [Input("oracleBgpPeeringIp")]
        public Input<string>? OracleBgpPeeringIp { get; set; }

        /// <summary>
        /// (Updatable) IPv6 is currently supported only in the Government Cloud. The IPv6 address for Oracle's end of the BGP session.  Only subnet masks from /64 up to /127 are allowed. If the session goes from Oracle to a customer's edge router, the customer specifies this information. If the session goes from Oracle to a provider's edge router, the provider specifies this.
        /// 
        /// There's one exception: for a public virtual circuit, Oracle specifies the BGP IPv6 addresses.
        /// 
        /// Note that IPv6 addressing is currently supported only in certain regions. See [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
        /// 
        /// Example: `2001:db8::2/64`
        /// </summary>
        [Input("oracleBgpPeeringIpv6")]
        public Input<string>? OracleBgpPeeringIpv6 { get; set; }

        /// <summary>
        /// (Updatable) The number of the specific VLAN (on the cross-connect or cross-connect group) that is assigned to this virtual circuit. Specified by the owner of the cross-connect or cross-connect group (the customer if the customer is colocated with Oracle, or the provider if the customer is connecting via provider).  Example: `200`
        /// </summary>
        [Input("vlan")]
        public Input<int>? Vlan { get; set; }

        public VirtualCircuitCrossConnectMappingArgs()
        {
        }
        public static new VirtualCircuitCrossConnectMappingArgs Empty => new VirtualCircuitCrossConnectMappingArgs();
    }
}
