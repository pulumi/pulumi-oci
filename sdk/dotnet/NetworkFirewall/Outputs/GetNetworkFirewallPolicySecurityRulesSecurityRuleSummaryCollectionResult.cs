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
    public sealed class GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionResult(ImmutableArray<Outputs.GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
