// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    public static class GetNetworkFirewallPolicyUrlLists
    {
        /// <summary>
        /// This data source provides the list of Network Firewall Policy Url Lists in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of URL lists for the Network Firewall Policy.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testNetworkFirewallPolicyUrlLists = Oci.NetworkFirewall.GetNetworkFirewallPolicyUrlLists.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id,
        ///         DisplayName = @var.Network_firewall_policy_url_list_display_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetNetworkFirewallPolicyUrlListsResult> InvokeAsync(GetNetworkFirewallPolicyUrlListsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkFirewallPolicyUrlListsResult>("oci:NetworkFirewall/getNetworkFirewallPolicyUrlLists:getNetworkFirewallPolicyUrlLists", args ?? new GetNetworkFirewallPolicyUrlListsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Network Firewall Policy Url Lists in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of URL lists for the Network Firewall Policy.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testNetworkFirewallPolicyUrlLists = Oci.NetworkFirewall.GetNetworkFirewallPolicyUrlLists.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id,
        ///         DisplayName = @var.Network_firewall_policy_url_list_display_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetNetworkFirewallPolicyUrlListsResult> Invoke(GetNetworkFirewallPolicyUrlListsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyUrlListsResult>("oci:NetworkFirewall/getNetworkFirewallPolicyUrlLists:getNetworkFirewallPolicyUrlLists", args ?? new GetNetworkFirewallPolicyUrlListsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkFirewallPolicyUrlListsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetNetworkFirewallPolicyUrlListsFilterArgs>? _filters;
        public List<Inputs.GetNetworkFirewallPolicyUrlListsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNetworkFirewallPolicyUrlListsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public string NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyUrlListsArgs()
        {
        }
        public static new GetNetworkFirewallPolicyUrlListsArgs Empty => new GetNetworkFirewallPolicyUrlListsArgs();
    }

    public sealed class GetNetworkFirewallPolicyUrlListsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetNetworkFirewallPolicyUrlListsFilterInputArgs>? _filters;
        public InputList<Inputs.GetNetworkFirewallPolicyUrlListsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNetworkFirewallPolicyUrlListsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyUrlListsInvokeArgs()
        {
        }
        public static new GetNetworkFirewallPolicyUrlListsInvokeArgs Empty => new GetNetworkFirewallPolicyUrlListsInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkFirewallPolicyUrlListsResult
    {
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string NetworkFirewallPolicyId;
        /// <summary>
        /// The list of url_list_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionResult> UrlListSummaryCollections;

        [OutputConstructor]
        private GetNetworkFirewallPolicyUrlListsResult(
            string? displayName,

            ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsFilterResult> filters,

            string id,

            string networkFirewallPolicyId,

            ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionResult> urlListSummaryCollections)
        {
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
            UrlListSummaryCollections = urlListSummaryCollections;
        }
    }
}