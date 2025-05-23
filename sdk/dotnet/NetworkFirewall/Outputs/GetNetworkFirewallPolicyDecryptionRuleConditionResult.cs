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
    public sealed class GetNetworkFirewallPolicyDecryptionRuleConditionResult
    {
        /// <summary>
        /// An array of IP address list names to be evaluated against the traffic destination address.
        /// </summary>
        public readonly ImmutableArray<string> DestinationAddresses;
        /// <summary>
        /// An array of IP address list names to be evaluated against the traffic source address.
        /// </summary>
        public readonly ImmutableArray<string> SourceAddresses;

        [OutputConstructor]
        private GetNetworkFirewallPolicyDecryptionRuleConditionResult(
            ImmutableArray<string> destinationAddresses,

            ImmutableArray<string> sourceAddresses)
        {
            DestinationAddresses = destinationAddresses;
            SourceAddresses = sourceAddresses;
        }
    }
}
