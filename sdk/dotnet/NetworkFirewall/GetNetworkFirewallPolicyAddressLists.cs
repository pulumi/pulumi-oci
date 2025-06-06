// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    public static class GetNetworkFirewallPolicyAddressLists
    {
        /// <summary>
        /// This data source provides the list of Network Firewall Policy Address Lists in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Network Firewall Policies.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testNetworkFirewallPolicyAddressLists = Oci.NetworkFirewall.GetNetworkFirewallPolicyAddressLists.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyAddressListDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNetworkFirewallPolicyAddressListsResult> InvokeAsync(GetNetworkFirewallPolicyAddressListsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkFirewallPolicyAddressListsResult>("oci:NetworkFirewall/getNetworkFirewallPolicyAddressLists:getNetworkFirewallPolicyAddressLists", args ?? new GetNetworkFirewallPolicyAddressListsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Network Firewall Policy Address Lists in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Network Firewall Policies.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testNetworkFirewallPolicyAddressLists = Oci.NetworkFirewall.GetNetworkFirewallPolicyAddressLists.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyAddressListDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkFirewallPolicyAddressListsResult> Invoke(GetNetworkFirewallPolicyAddressListsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyAddressListsResult>("oci:NetworkFirewall/getNetworkFirewallPolicyAddressLists:getNetworkFirewallPolicyAddressLists", args ?? new GetNetworkFirewallPolicyAddressListsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Network Firewall Policy Address Lists in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Network Firewall Policies.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testNetworkFirewallPolicyAddressLists = Oci.NetworkFirewall.GetNetworkFirewallPolicyAddressLists.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyAddressListDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkFirewallPolicyAddressListsResult> Invoke(GetNetworkFirewallPolicyAddressListsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyAddressListsResult>("oci:NetworkFirewall/getNetworkFirewallPolicyAddressLists:getNetworkFirewallPolicyAddressLists", args ?? new GetNetworkFirewallPolicyAddressListsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkFirewallPolicyAddressListsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetNetworkFirewallPolicyAddressListsFilterArgs>? _filters;
        public List<Inputs.GetNetworkFirewallPolicyAddressListsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNetworkFirewallPolicyAddressListsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public string NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyAddressListsArgs()
        {
        }
        public static new GetNetworkFirewallPolicyAddressListsArgs Empty => new GetNetworkFirewallPolicyAddressListsArgs();
    }

    public sealed class GetNetworkFirewallPolicyAddressListsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetNetworkFirewallPolicyAddressListsFilterInputArgs>? _filters;
        public InputList<Inputs.GetNetworkFirewallPolicyAddressListsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNetworkFirewallPolicyAddressListsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyAddressListsInvokeArgs()
        {
        }
        public static new GetNetworkFirewallPolicyAddressListsInvokeArgs Empty => new GetNetworkFirewallPolicyAddressListsInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkFirewallPolicyAddressListsResult
    {
        /// <summary>
        /// The list of address_list_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionResult> AddressListSummaryCollections;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyAddressListsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string NetworkFirewallPolicyId;

        [OutputConstructor]
        private GetNetworkFirewallPolicyAddressListsResult(
            ImmutableArray<Outputs.GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionResult> addressListSummaryCollections,

            string? displayName,

            ImmutableArray<Outputs.GetNetworkFirewallPolicyAddressListsFilterResult> filters,

            string id,

            string networkFirewallPolicyId)
        {
            AddressListSummaryCollections = addressListSummaryCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
        }
    }
}
