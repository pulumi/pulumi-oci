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
    public sealed class GetNetworkFirewallPolicyServicePortRangeResult
    {
        /// <summary>
        /// The maximum port in the range (inclusive), which may be absent for a single-port range.
        /// </summary>
        public readonly int MaximumPort;
        /// <summary>
        /// The minimum port in the range (inclusive), or the sole port of a single-port range.
        /// </summary>
        public readonly int MinimumPort;

        [OutputConstructor]
        private GetNetworkFirewallPolicyServicePortRangeResult(
            int maximumPort,

            int minimumPort)
        {
            MaximumPort = maximumPort;
            MinimumPort = minimumPort;
        }
    }
}