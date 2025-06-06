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
    public sealed class NetworkFirewallPolicyServicePortRange
    {
        /// <summary>
        /// (Updatable) The maximum port in the range (inclusive), which may be absent for a single-port range.
        /// </summary>
        public readonly int? MaximumPort;
        /// <summary>
        /// (Updatable) The minimum port in the range (inclusive), or the sole port of a single-port range.
        /// </summary>
        public readonly int MinimumPort;

        [OutputConstructor]
        private NetworkFirewallPolicyServicePortRange(
            int? maximumPort,

            int minimumPort)
        {
            MaximumPort = maximumPort;
            MinimumPort = minimumPort;
        }
    }
}
