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
    public sealed class GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionResult(ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
