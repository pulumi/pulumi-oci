// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Outputs
{

    [OutputType]
    public sealed class GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionResult(ImmutableArray<Outputs.GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
