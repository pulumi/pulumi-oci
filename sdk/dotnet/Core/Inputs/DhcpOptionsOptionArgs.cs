// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class DhcpOptionsOptionArgs : global::Pulumi.ResourceArgs
    {
        [Input("customDnsServers")]
        private InputList<string>? _customDnsServers;

        /// <summary>
        /// (Updatable) If you set `serverType` to `CustomDnsServer`, specify the IP address of at least one DNS server of your choice (three maximum).
        /// </summary>
        public InputList<string> CustomDnsServers
        {
            get => _customDnsServers ?? (_customDnsServers = new InputList<string>());
            set => _customDnsServers = value;
        }

        [Input("searchDomainNames")]
        private InputList<string>? _searchDomainNames;

        /// <summary>
        /// (Updatable) A single search domain name according to [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123). During a DNS query, the OS will append this search domain name to the value being queried.
        /// </summary>
        public InputList<string> SearchDomainNames
        {
            get => _searchDomainNames ?? (_searchDomainNames = new InputList<string>());
            set => _searchDomainNames = value;
        }

        /// <summary>
        /// (Updatable) 
        /// * **VcnLocal:** Reserved for future use.
        /// * **VcnLocalPlusInternet:** Also referred to as "Internet and VCN Resolver". Instances can resolve internet hostnames (no internet gateway is required), and can resolve hostnames of instances in the VCN. This is the default value in the default set of DHCP options in the VCN. For the Internet and VCN Resolver to work across the VCN, there must also be a DNS label set for the VCN, a DNS label set for each subnet, and a hostname for each instance. The Internet and VCN Resolver also enables reverse DNS lookup, which lets you determine the hostname corresponding to the private IP address. For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
        /// * **CustomDnsServer:** Instances use a DNS server of your choice (three maximum).
        /// </summary>
        [Input("serverType")]
        public Input<string>? ServerType { get; set; }

        /// <summary>
        /// (Updatable) The specific DHCP option. Either `DomainNameServer` (for [DhcpDnsOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpDnsOption/)) or `SearchDomain` (for [DhcpSearchDomainOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpSearchDomainOption/)).
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DhcpOptionsOptionArgs()
        {
        }
        public static new DhcpOptionsOptionArgs Empty => new DhcpOptionsOptionArgs();
    }
}