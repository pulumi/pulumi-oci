// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    public static class GetNetworkFirewallPolicyAddressList
    {
        /// <summary>
        /// This data source provides details about a specific Network Firewall Policy Address List resource in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Get Address List by the given name in the context of network firewall policy.
        /// </summary>
        public static Task<GetNetworkFirewallPolicyAddressListResult> InvokeAsync(GetNetworkFirewallPolicyAddressListArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkFirewallPolicyAddressListResult>("oci:NetworkFirewall/getNetworkFirewallPolicyAddressList:getNetworkFirewallPolicyAddressList", args ?? new GetNetworkFirewallPolicyAddressListArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Firewall Policy Address List resource in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Get Address List by the given name in the context of network firewall policy.
        /// </summary>
        public static Output<GetNetworkFirewallPolicyAddressListResult> Invoke(GetNetworkFirewallPolicyAddressListInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyAddressListResult>("oci:NetworkFirewall/getNetworkFirewallPolicyAddressList:getNetworkFirewallPolicyAddressList", args ?? new GetNetworkFirewallPolicyAddressListInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkFirewallPolicyAddressListArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique name to identify the group of addresses to be used in the policy rules.
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public string NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyAddressListArgs()
        {
        }
        public static new GetNetworkFirewallPolicyAddressListArgs Empty => new GetNetworkFirewallPolicyAddressListArgs();
    }

    public sealed class GetNetworkFirewallPolicyAddressListInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique name to identify the group of addresses to be used in the policy rules.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyAddressListInvokeArgs()
        {
        }
        public static new GetNetworkFirewallPolicyAddressListInvokeArgs Empty => new GetNetworkFirewallPolicyAddressListInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkFirewallPolicyAddressListResult
    {
        /// <summary>
        /// List of addresses.
        /// </summary>
        public readonly ImmutableArray<string> Addresses;
        public readonly string Id;
        /// <summary>
        /// Unique name to identify the group of addresses to be used in the policy rules.
        /// </summary>
        public readonly string Name;
        public readonly string NetworkFirewallPolicyId;
        /// <summary>
        /// OCID of the Network Firewall Policy this Address List belongs to.
        /// </summary>
        public readonly string ParentResourceId;
        /// <summary>
        /// Count of total Addresses in the AddressList
        /// </summary>
        public readonly int TotalAddresses;
        /// <summary>
        /// Type of address List.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetNetworkFirewallPolicyAddressListResult(
            ImmutableArray<string> addresses,

            string id,

            string name,

            string networkFirewallPolicyId,

            string parentResourceId,

            int totalAddresses,

            string type)
        {
            Addresses = addresses;
            Id = id;
            Name = name;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
            ParentResourceId = parentResourceId;
            TotalAddresses = totalAddresses;
            Type = type;
        }
    }
}