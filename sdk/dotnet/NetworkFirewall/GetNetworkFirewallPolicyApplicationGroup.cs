// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    public static class GetNetworkFirewallPolicyApplicationGroup
    {
        /// <summary>
        /// This data source provides details about a specific Network Firewall Policy Application Group resource in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Get ApplicationGroup by the given name in the context of network firewall policy.
        /// </summary>
        public static Task<GetNetworkFirewallPolicyApplicationGroupResult> InvokeAsync(GetNetworkFirewallPolicyApplicationGroupArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkFirewallPolicyApplicationGroupResult>("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroup:getNetworkFirewallPolicyApplicationGroup", args ?? new GetNetworkFirewallPolicyApplicationGroupArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Firewall Policy Application Group resource in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Get ApplicationGroup by the given name in the context of network firewall policy.
        /// </summary>
        public static Output<GetNetworkFirewallPolicyApplicationGroupResult> Invoke(GetNetworkFirewallPolicyApplicationGroupInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyApplicationGroupResult>("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroup:getNetworkFirewallPolicyApplicationGroup", args ?? new GetNetworkFirewallPolicyApplicationGroupInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Firewall Policy Application Group resource in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Get ApplicationGroup by the given name in the context of network firewall policy.
        /// </summary>
        public static Output<GetNetworkFirewallPolicyApplicationGroupResult> Invoke(GetNetworkFirewallPolicyApplicationGroupInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyApplicationGroupResult>("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroup:getNetworkFirewallPolicyApplicationGroup", args ?? new GetNetworkFirewallPolicyApplicationGroupInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkFirewallPolicyApplicationGroupArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Name of the application Group.
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public string NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyApplicationGroupArgs()
        {
        }
        public static new GetNetworkFirewallPolicyApplicationGroupArgs Empty => new GetNetworkFirewallPolicyApplicationGroupArgs();
    }

    public sealed class GetNetworkFirewallPolicyApplicationGroupInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Name of the application Group.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyApplicationGroupInvokeArgs()
        {
        }
        public static new GetNetworkFirewallPolicyApplicationGroupInvokeArgs Empty => new GetNetworkFirewallPolicyApplicationGroupInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkFirewallPolicyApplicationGroupResult
    {
        /// <summary>
        /// List of apps in the group.
        /// </summary>
        public readonly ImmutableArray<string> Apps;
        public readonly string Id;
        /// <summary>
        /// Name of the application Group.
        /// </summary>
        public readonly string Name;
        public readonly string NetworkFirewallPolicyId;
        /// <summary>
        /// OCID of the Network Firewall Policy this application group belongs to.
        /// </summary>
        public readonly string ParentResourceId;
        /// <summary>
        /// Count of total applications in the given application group.
        /// </summary>
        public readonly int TotalApps;

        [OutputConstructor]
        private GetNetworkFirewallPolicyApplicationGroupResult(
            ImmutableArray<string> apps,

            string id,

            string name,

            string networkFirewallPolicyId,

            string parentResourceId,

            int totalApps)
        {
            Apps = apps;
            Id = id;
            Name = name;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
            ParentResourceId = parentResourceId;
            TotalApps = totalApps;
        }
    }
}
