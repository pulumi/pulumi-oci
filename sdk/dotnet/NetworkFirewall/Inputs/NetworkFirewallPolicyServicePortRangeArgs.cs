// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Inputs
{

    public sealed class NetworkFirewallPolicyServicePortRangeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The maximum port in the range (inclusive), which may be absent for a single-port range.
        /// </summary>
        [Input("maximumPort")]
        public Input<int>? MaximumPort { get; set; }

        /// <summary>
        /// (Updatable) The minimum port in the range (inclusive), or the sole port of a single-port range.
        /// </summary>
        [Input("minimumPort", required: true)]
        public Input<int> MinimumPort { get; set; } = null!;

        public NetworkFirewallPolicyServicePortRangeArgs()
        {
        }
        public static new NetworkFirewallPolicyServicePortRangeArgs Empty => new NetworkFirewallPolicyServicePortRangeArgs();
    }
}
