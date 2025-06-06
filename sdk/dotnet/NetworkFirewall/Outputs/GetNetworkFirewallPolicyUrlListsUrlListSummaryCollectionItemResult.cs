// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Outputs
{

    [OutputType]
    public sealed class GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemResult
    {
        /// <summary>
        /// Unique name identifier for the URL list.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        public readonly string NetworkFirewallPolicyId;
        /// <summary>
        /// OCID of the Network Firewall Policy this URL List belongs to.
        /// </summary>
        public readonly string ParentResourceId;
        /// <summary>
        /// Total count of URLs in the URL List
        /// </summary>
        public readonly int TotalUrls;
        /// <summary>
        /// List of urls.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrlResult> Urls;

        [OutputConstructor]
        private GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemResult(
            string name,

            string networkFirewallPolicyId,

            string parentResourceId,

            int totalUrls,

            ImmutableArray<Outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrlResult> urls)
        {
            Name = name;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
            ParentResourceId = parentResourceId;
            TotalUrls = totalUrls;
            Urls = urls;
        }
    }
}
