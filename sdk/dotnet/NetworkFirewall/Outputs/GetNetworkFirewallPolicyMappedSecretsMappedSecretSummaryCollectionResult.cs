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
    public sealed class GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollectionResult(ImmutableArray<Outputs.GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
